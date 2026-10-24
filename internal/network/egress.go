package network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// EgressInfo 描述本机公网出口网络信息
type EgressInfo struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"` // ISO 3166-1 alpha-2 代码，例如 "CN", "US"
	CountryName string `json:"country_name"` // 国家或地区显示名称
	IsCN        bool   `json:"is_cn"`        // 是否为中国大陆出口
	Source      string `json:"source"`       // 检测数据来源接口
}

// EgressProvider 探测源定义
type EgressProvider struct {
	Name  string
	URL   string
	Parse func(body []byte) (*EgressInfo, error)
}

var ipipRegexIP = regexp.MustCompile(`当前\s*IP[：:]\s*([0-9a-fA-F:.]+)`)
var ipipRegexLoc = regexp.MustCompile(`来自于[：:]\s*([^\r\n]+)`)

// GetDefaultEgressProviders 返回默认的出口检测数据源列表
func GetDefaultEgressProviders() []EgressProvider {
	return []EgressProvider{
		{
			Name: "myip.ipip.net",
			URL:  "http://myip.ipip.net",
			Parse: func(body []byte) (*EgressInfo, error) {
				text := string(body)
				ipMatches := ipipRegexIP.FindStringSubmatch(text)
				if len(ipMatches) < 2 {
					return nil, errors.New("无法解析 IPIP 返回的 IP")
				}
				ip := strings.TrimSpace(ipMatches[1])
				loc := ""
				locMatches := ipipRegexLoc.FindStringSubmatch(text)
				if len(locMatches) >= 2 {
					loc = strings.TrimSpace(locMatches[1])
				}

				countryCode := "UNKNOWN"
				countryName := loc
				isCN := false

				if strings.Contains(loc, "中国") {
					if strings.Contains(loc, "香港") {
						countryCode = "HK"
					} else if strings.Contains(loc, "澳门") {
						countryCode = "MO"
					} else if strings.Contains(loc, "台湾") {
						countryCode = "TW"
					} else {
						countryCode = "CN"
						isCN = true
					}
				}

				return &EgressInfo{
					IP:          ip,
					CountryCode: countryCode,
					CountryName: countryName,
					IsCN:        isCN,
				}, nil
			},
		},
		{
			Name: "ip-api.com",
			URL:  "http://ip-api.com/json/?fields=status,message,country,countryCode,query",
			Parse: func(body []byte) (*EgressInfo, error) {
				var res struct {
					Status      string `json:"status"`
					Country     string `json:"country"`
					CountryCode string `json:"countryCode"`
					Query       string `json:"query"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					return nil, err
				}
				if res.Status != "success" || res.Query == "" {
					return nil, errors.New("ip-api 查询失败")
				}
				code := strings.ToUpper(res.CountryCode)
				return &EgressInfo{
					IP:          res.Query,
					CountryCode: code,
					CountryName: res.Country,
					IsCN:        code == "CN",
				}, nil
			},
		},
		{
			Name: "api.ip.sb",
			URL:  "https://api.ip.sb/geoip",
			Parse: func(body []byte) (*EgressInfo, error) {
				var res struct {
					IP          string `json:"ip"`
					Country     string `json:"country"`
					CountryCode string `json:"country_code"`
				}
				if err := json.Unmarshal(body, &res); err != nil {
					return nil, err
				}
				if res.IP == "" {
					return nil, errors.New("ip.sb 返回 IP 为空")
				}
				code := strings.ToUpper(res.CountryCode)
				return &EgressInfo{
					IP:          res.IP,
					CountryCode: code,
					CountryName: res.Country,
					IsCN:        code == "CN",
				}, nil
			},
		},
		{
			Name: "api4.ipify.org",
			URL:  "https://api4.ipify.org",
			Parse: func(body []byte) (*EgressInfo, error) {
				ip := strings.TrimSpace(string(body))
				if net.ParseIP(ip) == nil {
					return nil, errors.New("ipify 返回无效 IP")
				}
				return &EgressInfo{
					IP:          ip,
					CountryCode: "UNKNOWN",
				}, nil
			},
		},
	}
}

// CheckEgressWithClient 使用指定的 HTTP 客户端和数据源检测公网出口网络
func CheckEgressWithClient(ctx context.Context, client *http.Client, geoipPath string, providers ...EgressProvider) (*EgressInfo, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}
	if len(providers) == 0 {
		providers = GetDefaultEgressProviders()
	}

	var lastErr error
	for _, p := range providers {
		// 单次探测超时控制
		providerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		req, err := http.NewRequestWithContext(providerCtx, "GET", p.URL, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "curl/8.0.0 (RealityChecker)")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("[%s] 请求错误: %w", p.Name, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()

		if err != nil {
			lastErr = fmt.Errorf("[%s] 读取响应失败: %w", p.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("[%s] 响应状态码异常: %d", p.Name, resp.StatusCode)
			continue
		}

		info, err := p.Parse(body)
		if err != nil {
			lastErr = fmt.Errorf("[%s] 解析失败: %w", p.Name, err)
			continue
		}

		info.Source = p.Name
		// 结合本地 GeoIP mmdb 对归属地进行权威校验与补全
		enrichWithGeoIP(info, geoipPath, nil)

		return info, nil
	}

	return nil, fmt.Errorf("所有出口网络探测源均失败，最后错误: %w", lastErr)
}

// CheckEgress 使用默认 HTTP 客户端检测本机公网出口网络
func CheckEgress(ctx context.Context, geoipPath string) (*EgressInfo, error) {
	client := &http.Client{
		Timeout: 4 * time.Second,
	}
	return CheckEgressWithClient(ctx, client, geoipPath)
}

// CheckEgressWithReader 使用指定的 GeoIP Reader 检测本机公网出口网络
func CheckEgressWithReader(ctx context.Context, reader *geoip2.Reader, providers ...EgressProvider) (*EgressInfo, error) {
	client := &http.Client{
		Timeout: 4 * time.Second,
	}
	if len(providers) == 0 {
		providers = GetDefaultEgressProviders()
	}

	var lastErr error
	for _, p := range providers {
		providerCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		req, err := http.NewRequestWithContext(providerCtx, "GET", p.URL, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "curl/8.0.0 (RealityChecker)")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = fmt.Errorf("[%s] 请求错误: %w", p.Name, err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()

		if err != nil {
			lastErr = fmt.Errorf("[%s] 读取响应失败: %w", p.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("[%s] 响应状态码异常: %d", p.Name, resp.StatusCode)
			continue
		}

		info, err := p.Parse(body)
		if err != nil {
			lastErr = fmt.Errorf("[%s] 解析失败: %w", p.Name, err)
			continue
		}

		info.Source = p.Name
		enrichWithGeoIP(info, "", reader)

		return info, nil
	}

	return nil, fmt.Errorf("所有出口网络探测源均失败，最后错误: %w", lastErr)
}

// enrichWithGeoIP 使用本地 Country.mmdb 或指定 Reader 补全与校验出口 IP 归属地
func enrichWithGeoIP(info *EgressInfo, geoipPath string, reader *geoip2.Reader) {
	if info == nil || info.IP == "" {
		return
	}

	var db *geoip2.Reader
	var shouldClose bool

	if reader != nil {
		db = reader
	} else if geoipPath != "" {
		if _, err := os.Stat(geoipPath); err == nil {
			if opened, err := geoip2.Open(geoipPath); err == nil {
				db = opened
				shouldClose = true
			}
		}
	}

	if db == nil {
		return
	}
	if shouldClose {
		defer db.Close()
	}

	parsedIP := net.ParseIP(info.IP)
	if parsedIP == nil {
		return
	}

	record, err := db.Country(parsedIP)
	if err != nil {
		return
	}

	if record.Country.IsoCode != "" {
		iso := strings.ToUpper(record.Country.IsoCode)
		info.CountryCode = iso
		info.IsCN = (iso == "CN")
		if zhName := record.Country.Names["zh-CN"]; zhName != "" {
			info.CountryName = zhName
		} else if enName := record.Country.Names["en"]; enName != "" {
			info.CountryName = enName
		}
	}
}

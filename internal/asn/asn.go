package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const defaultEndpoint = "https://stat.ripe.net/data/announced-prefixes/data.json"

// Client retrieves announced prefixes from the RIPE Stat API.
type Client struct {
	httpClient *http.Client
	endpoint   string
}

// NewClient creates an ASN client with a bounded request timeout.
func NewClient(timeout ...time.Duration) *Client {
	requestTimeout := 15 * time.Second
	if len(timeout) > 0 && timeout[0] > 0 {
		requestTimeout = timeout[0]
	}
	return &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		endpoint:   defaultEndpoint,
	}
}

// PrefixesForIP resolves the originating ASN and returns its announced prefixes.
func (c *Client) PrefixesForIP(ctx context.Context, ip string) (int, []string, error) {
	parsed, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return 0, nil, fmt.Errorf("解析入口IP失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://stat.ripe.net/data/prefix-overview/data.json?resource="+parsed.String(), nil)
	if err != nil {
		return 0, nil, fmt.Errorf("创建IP ASN请求失败: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("查询IP ASN失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("查询IP ASN失败: HTTP %s", resp.Status)
	}
	var overview struct {
		Data struct {
			ASNs []struct {
				ASN int `json:"asn"`
			} `json:"asns"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&overview); err != nil {
		return 0, nil, fmt.Errorf("解析IP ASN响应失败: %w", err)
	}
	if len(overview.Data.ASNs) == 0 || overview.Data.ASNs[0].ASN <= 0 {
		return 0, nil, fmt.Errorf("RIPEstat未返回%s的ASN", parsed)
	}
	asnNumber := overview.Data.ASNs[0].ASN
	prefixes, err := c.FetchPrefixes(ctx, fmt.Sprintf("AS%d", asnNumber))
	if err != nil {
		return 0, nil, err
	}
	return asnNumber, prefixes, nil
}

type response struct {
	Data struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
}

// FetchPrefixes returns the currently announced, normalized CIDR prefixes.
func (c *Client) FetchPrefixes(ctx context.Context, resource string) ([]string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return nil, fmt.Errorf("ASN不能为空")
	}
	if !strings.HasPrefix(strings.ToUpper(resource), "AS") {
		resource = "AS" + resource
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("创建ASN请求失败: %w", err)
	}
	query := req.URL.Query()
	query.Set("resource", resource)
	req.URL.RawQuery = query.Encode()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("查询%s前缀失败: %w", resource, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询%s前缀失败: HTTP %s", resource, resp.Status)
	}

	var payload response
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析%s前缀响应失败: %w", resource, err)
	}

	prefixes := make([]string, 0, len(payload.Data.Prefixes))
	seen := make(map[string]struct{}, len(payload.Data.Prefixes))
	for _, item := range payload.Data.Prefixes {
		_, network, err := net.ParseCIDR(item.Prefix)
		if err != nil {
			continue
		}
		prefix := network.String()
		if _, ok := seen[prefix]; !ok {
			seen[prefix] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("%s没有可用的已公告前缀", resource)
	}
	return prefixes, nil
}

// FilterByCountry keeps prefixes whose network address belongs to country.
// Country accepts an ISO alpha-2 code (for example CN or US) or a GeoIP name.
func FilterByCountry(prefixes []string, db *geoip2.Reader, country string) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("GeoIP数据库未加载")
	}
	country = strings.TrimSpace(country)
	if country == "" {
		return nil, fmt.Errorf("国家不能为空")
	}
	country = strings.ToUpper(country)

	filtered := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		record, err := db.Country(network.IP)
		if err != nil {
			continue
		}
		if strings.EqualFold(record.Country.IsoCode, country) ||
			strings.EqualFold(record.Country.Names["en"], country) ||
			strings.EqualFold(record.Country.Names["zh-CN"], country) {
			filtered = append(filtered, network.String())
		}
	}
	return filtered, nil
}

// FilterIPVersion 根据 IPv4/IPv6 偏好过滤 CIDR 前缀
func FilterIPVersion(prefixes []string, ipv4Only, ipv6Only bool) []string {
	if !ipv4Only && !ipv6Only {
		return prefixes
	}
	filtered := make([]string, 0, len(prefixes))
	for _, raw := range prefixes {
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		isIPv4 := network.IP.To4() != nil
		if ipv4Only && isIPv4 {
			filtered = append(filtered, network.String())
		} else if ipv6Only && !isIPv4 {
			filtered = append(filtered, network.String())
		}
	}
	return filtered
}


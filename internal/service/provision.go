package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"RealityChecker/internal/asn"
	"RealityChecker/internal/config"
	"RealityChecker/internal/core"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"

	"github.com/oschwald/geoip2-golang"
)

// ProvisionRequest 目标供给请求参数
type ProvisionRequest struct {
	IP          string        `json:"ip"`
	Limit       int           `json:"limit"`
	MinStars    int           `json:"min_stars"`
	MaxAge      time.Duration `json:"max_age"`
	Fresh       bool          `json:"fresh"`
	Country     string        `json:"country,omitempty"`
	IPv4Only    bool          `json:"ipv4_only"`
	IPv6Only    bool          `json:"ipv6_only"`
	RequireNoCN bool          `json:"require_no_cn"`
}

// TargetItem 标准化优质目标输出
type TargetItem struct {
	Source          string    `json:"source"` // "cache" 或 "scan"
	Domain          string    `json:"domain"`
	IP              string    `json:"ip"`
	ASN             string    `json:"asn"`
	Country         string    `json:"country"`
	Stars           int       `json:"stars"`
	HandshakeMS     int64     `json:"handshake_ms"`
	CertDays        int       `json:"cert_days"`
	StatusCode      int       `json:"status_code"`
	PageTitle       string    `json:"page_title,omitempty"`
	IsCDN           bool      `json:"is_cdn"`
	IsDefaultPage   bool      `json:"is_default_page"`
	DefaultPageType string    `json:"default_page_type,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// ProvisionEvent SSE 流式事件载体
type ProvisionEvent struct {
	Event string `json:"event"` // "init", "target", "progress", "done", "error"
	Data  any    `json:"data"`
}

// InitEventData 任务初始化元数据
type InitEventData struct {
	IP         string   `json:"ip"`
	ASN        string   `json:"asn"`
	Country    string   `json:"country"`
	Need       int      `json:"need"`
	CIDRCount  int      `json:"cidr_count"`
	CachedHits int      `json:"cached_hits"`
	Prefixes   []string `json:"prefixes,omitempty"`
}

// ProgressEventData 实时扫描进度数据
type ProgressEventData struct {
	ScannedIPs  int64  `json:"scanned_ips"`
	CurrentCIDR string `json:"current_cidr"`
	CurrentIP   string `json:"current_ip"`
}

// DoneEventData 结束元数据
type DoneEventData struct {
	TotalFound int    `json:"total_found"`
	FromCache  int    `json:"from_cache"`
	FromScan   int    `json:"from_scan"`
	Reason     string `json:"reason"` // "cache_full", "limit_hit", "scan_exhausted", "timeout", "cancelled"
}

// ProvisionService 提供端到端目标发现与流式供给业务能力
type ProvisionService struct {
	store       *storage.TargetStore
	geoipReader *geoip2.Reader
	asnClient   asn.ASNResolver
	appConfig   *types.Config
}

// NewProvisionService 创建供给服务实例
func NewProvisionService(
	store *storage.TargetStore,
	geoipReader *geoip2.Reader,
	asnClient asn.ASNResolver,
	cfg *types.Config,
) *ProvisionService {
	if asnClient == nil {
		asnClient = asn.NewClient(15 * time.Second)
	}
	if cfg == nil {
		cfg, _ = config.LoadConfig("")
	}
	return &ProvisionService{
		store:       store,
		geoipReader: geoipReader,
		asnClient:   asnClient,
		appConfig:   cfg,
	}
}

// StreamTargets 执行渐进式目标发现：优先本地有效缓存，不足时触发实时扫描补齐
func (s *ProvisionService) StreamTargets(ctx context.Context, req ProvisionRequest, emit func(evt ProvisionEvent) error) error {
	// 1. 参数校验与补齐默认值
	targetIP := strings.TrimSpace(req.IP)
	if targetIP == "" {
		err := errors.New("missing ip parameter")
		_ = emit(ProvisionEvent{Event: "error", Data: map[string]string{"error": err.Error()}})
		return err
	}
	parsedIP := net.ParseIP(targetIP)
	if parsedIP == nil {
		err := fmt.Errorf("invalid ip address: %s", targetIP)
		_ = emit(ProvisionEvent{Event: "error", Data: map[string]string{"error": err.Error()}})
		return err
	}

	if req.Limit <= 0 {
		req.Limit = 5
	}
	if req.Limit > 50 {
		req.Limit = 50
	}
	if req.MinStars <= 0 {
		req.MinStars = 3
	}
	if req.MaxAge <= 0 {
		req.MaxAge = 7 * 24 * time.Hour // 默认 7 天内有效
	}

	// 2. 解析地理位置与 ASN 前缀
	var country string
	if s.geoipReader != nil {
		if rec, err := s.geoipReader.Country(parsedIP); err == nil && rec.Country.IsoCode != "" {
			country = strings.ToUpper(rec.Country.IsoCode)
		}
	}
	if req.Country != "" {
		country = strings.ToUpper(strings.TrimSpace(req.Country))
	}

	asnNumber, prefixes, err := s.asnClient.PrefixesForIP(ctx, targetIP)
	if err != nil {
		_ = emit(ProvisionEvent{Event: "error", Data: map[string]string{"error": fmt.Sprintf("lookup asn for ip %s failed: %v", targetIP, err)}})
		return err
	}
	asnStr := fmt.Sprintf("AS%d", asnNumber)

	// 3. 过滤同国家与同协议族 CIDR
	matchedCIDRs := make([]string, 0, len(prefixes))
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		if req.IPv4Only && !prefix.Addr().Is4() {
			continue
		}
		if req.IPv6Only && !prefix.Addr().Is6() {
			continue
		}
		if s.geoipReader != nil && country != "" {
			if rec, err := s.geoipReader.Country(net.ParseIP(prefix.Addr().String())); err == nil {
				if !strings.EqualFold(rec.Country.IsoCode, country) {
					continue
				}
			}
		}
		matchedCIDRs = append(matchedCIDRs, prefix.String())
	}

	var fromCacheCount int
	var fromScanCount int
	seenDomains := make(map[string]bool)

	// 4. 阶段一：本地资产缓存优先 (0 延迟即时推送)
	if !req.Fresh && s.store != nil {
		cachedTargets, err := s.store.GetTargetsByASN(asnStr, country, req.MaxAge)
		if err == nil && len(cachedTargets) > 0 {
			for _, rec := range cachedTargets {
				if rec == nil || rec.Domain == "" {
					continue
				}
				if rec.Stars < req.MinStars {
					continue
				}
				dLower := strings.ToLower(rec.Domain)
				if req.RequireNoCN && (strings.HasSuffix(dLower, ".cn") || strings.Contains(dLower, ".edu.cn") || strings.Contains(dLower, ".gov.cn")) {
					continue
				}
				if seenDomains[rec.Domain] {
					continue
				}
				seenDomains[rec.Domain] = true
				fromCacheCount++

				item := TargetItem{
					Source:          "cache",
					Domain:          rec.Domain,
					IP:              rec.IP,
					ASN:             rec.ASN,
					Country:         rec.Country,
					Stars:           rec.Stars,
					HandshakeMS:     rec.HandshakeMS,
					CertDays:        rec.CertDays,
					StatusCode:      rec.StatusCode,
					PageTitle:       rec.PageTitle,
					IsCDN:           rec.IsCDN,
					IsDefaultPage:   rec.IsDefaultPage,
					DefaultPageType: rec.DefaultPageType,
					CreatedAt:       rec.LastCheckedAt,
				}

				// 发送初始事件（如果还未发）
				if fromCacheCount == 1 {
					_ = emit(ProvisionEvent{
						Event: "init",
						Data: InitEventData{
							IP:         targetIP,
							ASN:        asnStr,
							Country:    country,
							Need:       req.Limit,
							CIDRCount:  len(matchedCIDRs),
							CachedHits: len(cachedTargets),
						},
					})
				}

				if err := emit(ProvisionEvent{Event: "target", Data: item}); err != nil {
					return err
				}

				// 达到目标上限，直接命中缓存收工！
				if fromCacheCount >= req.Limit {
					return emit(ProvisionEvent{
						Event: "done",
						Data: DoneEventData{
							TotalFound: fromCacheCount,
							FromCache:  fromCacheCount,
							FromScan:   0,
							Reason:     "cache_full",
						},
					})
				}
			}
		}
	}

	// 如果未命中缓存或缓存不足以发出 init 事件，在此补发 init 事件
	if fromCacheCount == 0 {
		_ = emit(ProvisionEvent{
			Event: "init",
			Data: InitEventData{
				IP:         targetIP,
				ASN:        asnStr,
				Country:    country,
				Need:       req.Limit,
				CIDRCount:  len(matchedCIDRs),
				CachedHits: 0,
			},
		})
	}

	// 5. 阶段二：现场按需补齐扫描 (即扫即推)
	needed := req.Limit - fromCacheCount
	if needed <= 0 || len(matchedCIDRs) == 0 {
		return emit(ProvisionEvent{
			Event: "done",
			Data: DoneEventData{
				TotalFound: fromCacheCount,
				FromCache:  fromCacheCount,
				FromScan:   0,
				Reason:     "limit_reached",
			},
		})
	}

	scannerEngine := scanner.NewScanner()
	defer scannerEngine.Close()

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	engine := core.NewEngine(s.appConfig)

	var lastProgressTime time.Time
	var progressMu sync.Mutex
	var totalScannedIPs int64

	scanEvents := core.AutoScanEvents{
		OnIPScanned: func(delta int, currentCIDR string, currentIP string, currentIdx int, totalCIDRs int) {
			newTotal := atomic.AddInt64(&totalScannedIPs, int64(delta))
			progressMu.Lock()
			now := time.Now()
			if now.Sub(lastProgressTime) >= 300*time.Millisecond {
				lastProgressTime = now
				progressMu.Unlock()
				_ = emit(ProvisionEvent{
					Event: "progress",
					Data: ProgressEventData{
						ScannedIPs:  newTotal,
						CurrentCIDR: currentCIDR,
						CurrentIP:   currentIP,
					},
				})
			} else {
				progressMu.Unlock()
			}
		},
		OnTargetFound: func(res *types.DetectionResult, count int, ip string, handshakeMs int64, statusCode int) {
			if res == nil || res.Domain == "" {
				return
			}
			if seenDomains[res.Domain] {
				return
			}
			stars := core.CalculateTargetStars(res)
			if stars < req.MinStars {
				return
			}
			seenDomains[res.Domain] = true
			fromScanCount++

			rec := storage.DetectionResultToRecord(res, asnStr, country, ip, stars)
			item := TargetItem{
				Source:          "scan",
				Domain:          rec.Domain,
				IP:              rec.IP,
				ASN:             rec.ASN,
				Country:         rec.Country,
				Stars:           rec.Stars,
				HandshakeMS:     rec.HandshakeMS,
				CertDays:        rec.CertDays,
				StatusCode:      rec.StatusCode,
				PageTitle:       rec.PageTitle,
				IsCDN:           rec.IsCDN,
				IsDefaultPage:   rec.IsDefaultPage,
				DefaultPageType: rec.DefaultPageType,
				CreatedAt:       rec.LastCheckedAt,
			}

			_ = emit(ProvisionEvent{Event: "target", Data: item})

			// 凑够即停，主动刹车
			if fromCacheCount+fromScanCount >= req.Limit {
				cancelScan()
			}
		},
	}

	filterConfig := types.RealityFilterConfig{
		MinStars:    req.MinStars,
		RequireNoCN: req.RequireNoCN,
		IPv4Only:    req.IPv4Only,
		IPv6Only:    req.IPv6Only,
		NoResume:    true, // 现场按需扫描无需加载断点记录
	}

	autoCfg := core.AutoScanConfig{
		CIDRs:      matchedCIDRs,
		MaxTargets: needed,
		CheckAll:   false,
		Filter:     filterConfig,
		ASN:        asnStr,
		Country:    country,
	}

	autoScanner := core.NewAutoScanner(engine, s.store, scannerEngine, autoCfg, scanEvents)
	_, scanErr := autoScanner.Run(scanCtx)

	reason := "scan_exhausted"
	if fromCacheCount+fromScanCount >= req.Limit {
		reason = "limit_hit"
	} else if scanCtx.Err() == context.Canceled && ctx.Err() == nil {
		reason = "limit_hit"
	} else if ctx.Err() != nil {
		reason = "cancelled"
	} else if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		reason = "scan_error: " + scanErr.Error()
	}

	return emit(ProvisionEvent{
		Event: "done",
		Data: DoneEventData{
			TotalFound: fromCacheCount + fromScanCount,
			FromCache:  fromCacheCount,
			FromScan:   fromScanCount,
			Reason:     reason,
		},
	})
}

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
	ScanAll     bool          `json:"scan_all"`
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

// RankedTargetItem 经过智能动态加权评分的目标资产
type RankedTargetItem struct {
	TargetItem
	MatchLevel string `json:"match_level"` // "same_asn" (同ASN极速直连), "same_country" (同国家骨干), "global" (全球优质)
	Score      int    `json:"score"`       // 动态综合加权总分
}

// TargetSummaryInfo 目标 IP 所属网络元数据摘要
type TargetSummaryInfo struct {
	TargetIP           string `json:"target_ip"`
	ASN                string `json:"asn"`
	ASNName            string `json:"asn_name,omitempty"`
	Country            string `json:"country"`
	IPType             string `json:"ip_type"`             // "datacenter" (机房) 或 "residential" (家宽)
	IsResidential      bool   `json:"is_residential"`     // 是否为住宅宽带
	SuggestScan        bool   `json:"suggest_scan"`        // 是否建议扫描 (机房为 true，家宽因几乎无网站为 false)
	CIDRCount          int    `json:"cidr_count"`
	TotalIPs           int64  `json:"total_ips"`
	HasCheckpoint      bool   `json:"has_checkpoint"`
	LastCheckpointIP   string `json:"last_checkpoint_ip,omitempty"`
	CompletedCIDRCount int    `json:"completed_cidr_count"`
	SameASNHits        int    `json:"same_asn_hits"`
	TotalHits          int    `json:"total_hits"`
}


// ProvisionEvent SSE 流式事件载体
type ProvisionEvent struct {
	Event string `json:"event"` // "init", "target", "progress", "done", "error"
	Data  any    `json:"data"`
}

// InitEventData 任务初始化元数据
type InitEventData struct {
	IP               string   `json:"ip"`
	ASN              string   `json:"asn"`
	ASNName          string   `json:"asn_name,omitempty"`
	Country          string   `json:"country"`
	IPType           string   `json:"ip_type"`             // "datacenter" 或 "residential"
	IsResidential    bool     `json:"is_residential"`
	SuggestScan      bool     `json:"suggest_scan"`
	Need             int      `json:"need"`
	CIDRCount        int      `json:"cidr_count"`
	TotalIPs         int64    `json:"total_ips"`
	CachedHits       int      `json:"cached_hits"`
	HasCheckpoint    bool     `json:"has_checkpoint"`
	LastCheckpointIP string   `json:"last_checkpoint_ip,omitempty"`
	Prefixes         []string `json:"prefixes,omitempty"`
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
	if cfg == nil {
		cfg, _ = config.LoadConfig("")
	}
	if asnClient == nil {
		proxyURL := ""
		if cfg != nil && cfg.Proxy.Download && cfg.Proxy.URL != "" {
			proxyURL = cfg.Proxy.URL
		}
		asnClient = asn.NewClientWithProxy(proxyURL, 15*time.Second)
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

	var cachedTargets []*types.TargetRecord
	if !req.Fresh && s.store != nil {
		cachedTargets, _ = s.store.GetTargetsByASN(asnStr, country, req.MaxAge)
	}

	var hasCheckpoint bool
	var lastCheckpointIP string
	if s.store != nil {
		if cps, err := s.store.GetCheckpoints(asnStr); err == nil && len(cps) > 0 {
			hasCheckpoint = true
			for _, cp := range cps {
				if !cp.Completed && cp.LastIP != "" {
					lastCheckpointIP = cp.LastIP
					break
				}
			}
		}
	}

	totalIPs := core.CalculateTotalIPs(matchedCIDRs)

	var asnProviderName string
	if s.store != nil {
		if record, err := s.store.GetASN(asnNumber); err == nil && record != nil && record.Name != "" {
			asnProviderName = record.Name
		}
	}
	ipType, isResidential, resolvedName := asn.ClassifyASN(asnNumber, asnProviderName)
	if asnProviderName == "" {
		asnProviderName = resolvedName
	}

	// 提前发出任务初始化元数据事件（Phase 0: 秒级首帧确认身份与规模）
	if err := emit(ProvisionEvent{
		Event: "init",
		Data: InitEventData{
			IP:               targetIP,
			ASN:              asnStr,
			ASNName:          asnProviderName,
			Country:          country,
			IPType:           ipType,
			IsResidential:    isResidential,
			SuggestScan:      !isResidential,
			Need:             req.Limit,
			CIDRCount:        len(matchedCIDRs),
			TotalIPs:         totalIPs,
			CachedHits:       len(cachedTargets),
			HasCheckpoint:    hasCheckpoint,
			LastCheckpointIP: lastCheckpointIP,
			Prefixes:         matchedCIDRs,
		},
	}); err != nil {
		return err
	}

	var fromCacheCount int
	var fromScanCount int
	seenDomains := make(map[string]bool)

	// 4. 阶段一：本地资产缓存优先 (0 延迟即时推送)
	if !req.Fresh && len(cachedTargets) > 0 {
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

			if err := emit(ProvisionEvent{Event: "target", Data: item}); err != nil {
				return err
			}

			// 达到目标上限且未要求全量扫描 ASN 时，直接命中缓存收工！
			if !req.ScanAll && fromCacheCount >= req.Limit {
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

	// 5. 阶段二：现场按需补齐扫描或全量 ASN 扫描 (即扫即推，支持单 IP 级断点续传)
	needed := req.Limit - fromCacheCount
	if !req.ScanAll && (needed <= 0 || len(matchedCIDRs) == 0) {
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

	scanProxy := ""
	if s.appConfig != nil && s.appConfig.Proxy.Scanner && s.appConfig.Proxy.URL != "" {
		scanProxy = s.appConfig.Proxy.URL
	}
	scannerEngine := scanner.NewScanner(scanProxy)
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

			// 凑够即停，主动刹车 (全量扫描模式时不按 limit 刹车)
			if !req.ScanAll && fromCacheCount+fromScanCount >= req.Limit {
				cancelScan()
			}
		},
	}

	filterConfig := types.RealityFilterConfig{
		MinStars:    req.MinStars,
		RequireNoCN: req.RequireNoCN,
		IPv4Only:    req.IPv4Only,
		IPv6Only:    req.IPv6Only,
		NoResume:    false, // 启用断点续传能力
	}

	maxTargets := needed
	if req.ScanAll {
		maxTargets = 0
	}

	autoCfg := core.AutoScanConfig{
		CIDRs:      matchedCIDRs,
		MaxTargets: maxTargets,
		CheckAll:   req.ScanAll,
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

// GetSmartTargets 基于用户指定的目标 IP，执行动态加权打分排序
// 核心规则：目标 IP 所属的 ASN 赋予最高基础分权重 (+1000)，同国家资产获得次高权重 (+250)
func (s *ProvisionService) GetSmartTargets(ctx context.Context, req ProvisionRequest) ([]RankedTargetItem, *TargetSummaryInfo, error) {
	if s.store == nil {
		return nil, nil, errors.New("storage store is nil")
	}

	targetIP := strings.TrimSpace(req.IP)
	var targetASN string
	var targetCountry string
	var prefixes []string
	var matchedCIDRs []string
	var cidrCount int
	var totalIPs int64
	var hasCheckpoint bool
	var lastCheckpointIP string
	var completedCIDRCount int

	var asnNum int
	// 1. 若提供了目标 IP，智能解析其 ASN 与国家及网段
	if targetIP != "" {
		if parsedIP := net.ParseIP(targetIP); parsedIP != nil {
			if s.geoipReader != nil {
				if rec, err := s.geoipReader.Country(parsedIP); err == nil && rec.Country.IsoCode != "" {
					targetCountry = strings.ToUpper(rec.Country.IsoCode)
				}
			}
			if num, rawPrefixes, err := s.asnClient.PrefixesForIP(ctx, targetIP); err == nil && num > 0 {
				asnNum = num
				targetASN = fmt.Sprintf("AS%d", asnNum)
				prefixes = rawPrefixes
			}
		}
	}

	if req.Country != "" {
		targetCountry = strings.ToUpper(strings.TrimSpace(req.Country))
	}

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
		if s.geoipReader != nil && targetCountry != "" {
			if rec, err := s.geoipReader.Country(net.ParseIP(prefix.Addr().String())); err == nil {
				if !strings.EqualFold(rec.Country.IsoCode, targetCountry) {
					continue
				}
			}
		}
		matchedCIDRs = append(matchedCIDRs, prefix.String())
	}
	cidrCount = len(matchedCIDRs)
	if cidrCount > 0 {
		totalIPs = core.CalculateTotalIPs(matchedCIDRs)
	}

	if targetASN != "" && s.store != nil {
		if cps, err := s.store.GetCheckpoints(targetASN); err == nil && len(cps) > 0 {
			hasCheckpoint = true
			for _, cp := range cps {
				if cp.Completed {
					completedCIDRCount++
				} else if cp.LastIP != "" && lastCheckpointIP == "" {
					lastCheckpointIP = cp.LastIP
				}
			}
		}
	}

	var asnProviderName string
	if s.store != nil && asnNum > 0 {
		if record, err := s.store.GetASN(asnNum); err == nil && record != nil && record.Name != "" {
			asnProviderName = record.Name
		}
	}
	ipType, isResidential, resolvedName := asn.ClassifyASN(asnNum, asnProviderName)
	if asnProviderName == "" {
		asnProviderName = resolvedName
	}

	if req.Limit <= 0 {
		req.Limit = 10
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	// 2. 从持久化资产库拉取所有活跃资产
	allTargets, err := s.store.GetAllTargets()
	if err != nil {
		return nil, nil, err
	}

	summary := &TargetSummaryInfo{
		TargetIP:           targetIP,
		ASN:                targetASN,
		ASNName:            asnProviderName,
		Country:            targetCountry,
		IPType:             ipType,
		IsResidential:      isResidential,
		SuggestScan:        !isResidential,
		CIDRCount:          cidrCount,
		TotalIPs:           totalIPs,
		HasCheckpoint:      hasCheckpoint,
		LastCheckpointIP:   lastCheckpointIP,
		CompletedCIDRCount: completedCIDRCount,
	}

	var ranked []RankedTargetItem
	targetASNNorm := strings.ToUpper(strings.TrimPrefix(targetASN, "AS"))

	for _, rec := range allTargets {
		if rec == nil || rec.Domain == "" || !rec.IsActive {
			continue
		}
		if req.MinStars > 0 && rec.Stars < req.MinStars {
			continue
		}

		dLower := strings.ToLower(rec.Domain)
		if req.RequireNoCN && (strings.HasSuffix(dLower, ".cn") || strings.Contains(dLower, ".edu.cn") || strings.Contains(dLower, ".gov.cn")) {
			continue
		}

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

		// 3. 动态智能加权打分模型
		score := 0
		matchLevel := "global"

		recASNNorm := strings.ToUpper(strings.TrimPrefix(rec.ASN, "AS"))
		isSameASN := (targetASNNorm != "" && recASNNorm != "" && targetASNNorm == recASNNorm)
		isSameCountry := (targetCountry != "" && strings.EqualFold(rec.Country, targetCountry))

		if isSameASN {
			matchLevel = "same_asn"
			score += 1000 // 🔥 同 ASN 权重提至最高置顶
			summary.SameASNHits++
		} else if isSameCountry {
			matchLevel = "same_country"
			score += 250 // 🌐 同国家骨干优质权重
		} else {
			matchLevel = "global"
			score += 50 // 🌍 全球优质储备
		}

		// 星级加成 (5星 +150, 4星 +120, 3星 +90)
		score += rec.Stars * 30

		// 握手延迟扣分 (延迟越低得分越高，最大扣除 150 分)
		if rec.HandshakeMS > 0 {
			penalty := int(rec.HandshakeMS / 3)
			if penalty > 150 {
				penalty = 150
			}
			score -= penalty
		}

		// 证书充足度奖励 (>30天 +20分)
		if rec.CertDays >= 30 {
			score += 20
		}

		// 避免非安全状态码
		if rec.StatusCode < 200 || rec.StatusCode >= 400 {
			score -= 50
		}

		ranked = append(ranked, RankedTargetItem{
			TargetItem: item,
			MatchLevel: matchLevel,
			Score:      score,
		})
	}

	summary.TotalHits = len(ranked)

	// 4. 严格按照加权得分从高到低排序
	for i := 0; i < len(ranked); i++ {
		for j := i + 1; j < len(ranked); j++ {
			if ranked[j].Score > ranked[i].Score {
				ranked[i], ranked[j] = ranked[j], ranked[i]
			}
		}
	}

	// 5. 截取 limit 条数
	if len(ranked) > req.Limit {
		ranked = ranked[:req.Limit]
	}

	return ranked, summary, nil
}

// CheckSingleDomain 在线即时检测单个域名/IP 并持久化至资产库
func (s *ProvisionService) CheckSingleDomain(ctx context.Context, domain, manualIP string) (*types.TargetRecord, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return nil, errors.New("domain cannot be empty")
	}

	pipeline := core.NewPipeline(nil, s.appConfig)
	res, err := pipeline.Execute(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("pipeline execution failed: %w", err)
	}

	var ipStr, asnStr, countryStr string
	if manualIP != "" {
		ipStr = manualIP
	} else if res.Network != nil && res.Network.FinalDomain != "" {
		ipStr = res.Network.FinalDomain
	}

	if ipStr != "" {
		if parsed := net.ParseIP(ipStr); parsed != nil {
			if s.geoipReader != nil {
				if rec, err := s.geoipReader.Country(parsed); err == nil {
					countryStr = strings.ToUpper(rec.Country.IsoCode)
				}
			}
			if asnNum, _, err := s.asnClient.PrefixesForIP(ctx, ipStr); err == nil && asnNum > 0 {
				asnStr = fmt.Sprintf("AS%d", asnNum)
			}
		}
	}

	stars := core.CalculateTargetStars(res)
	rec := storage.DetectionResultToRecord(res, asnStr, countryStr, ipStr, stars)
	if rec == nil {
		return nil, errors.New("failed to convert detection result to record")
	}

	if s.store != nil {
		if err := s.store.UpsertTarget(rec); err != nil {
			return nil, fmt.Errorf("failed to save target to database: %w", err)
		}
	}

	return rec, nil
}

// QueryTargets 资产检索代理
func (s *ProvisionService) QueryTargets(opts types.TargetQueryOptions) ([]*types.TargetRecord, int, error) {
	if s.store == nil {
		return nil, 0, errors.New("store not available")
	}
	return s.store.QueryTargets(opts)
}

// UpdateTargetActive 资产激活状态代理
func (s *ProvisionService) UpdateTargetActive(domain string, active bool) error {
	if s.store == nil {
		return errors.New("store not available")
	}
	return s.store.UpdateTargetActive(domain, active)
}

// DeleteTarget 物理删除资产代理
func (s *ProvisionService) DeleteTarget(domain string) error {
	if s.store == nil {
		return errors.New("store not available")
	}
	return s.store.DeleteTarget(domain)
}

// GetStats 资产概览统计代理
func (s *ProvisionService) GetStats() (*types.TargetStats, error) {
	if s.store == nil {
		return nil, errors.New("store not available")
	}
	return s.store.GetStats()
}

// ListASNs ASN 列表查询代理
func (s *ProvisionService) ListASNs(status string, minPriority, limit, offset int) ([]*types.ASNRecord, error) {
	if s.store == nil {
		return nil, errors.New("store not available")
	}
	return s.store.ListASNs(status, minPriority, limit, offset)
}


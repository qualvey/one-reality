package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"RealityChecker/internal/asn"
	"RealityChecker/internal/config"
	"RealityChecker/internal/core"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/network"
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
	Source          string     `json:"source"` // "cache" 或 "scan"
	Domain          string     `json:"domain"`
	IP              string     `json:"ip"`
	ASN             string     `json:"asn"`
	Country         string     `json:"country"`
	Stars           int        `json:"stars"`
	HandshakeMS     int64      `json:"handshake_ms"`
	CertDays        int        `json:"cert_days"`
	CertExpireAt    *time.Time `json:"cert_expire_at,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	StatusCode      int        `json:"status_code"`
	PageTitle       string     `json:"page_title,omitempty"`
	IsCDN           bool       `json:"is_cdn"`
	IsDefaultPage   bool       `json:"is_default_page"`
	DefaultPageType string     `json:"default_page_type,omitempty"`
	IsStarred       bool       `json:"is_starred"`
	IsDisliked      bool       `json:"is_disliked"`
	CreatedAt       time.Time  `json:"created_at"`
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
	IPType             string `json:"ip_type"`        // "datacenter" (机房) 或 "residential" (家宽)
	IsResidential      bool   `json:"is_residential"` // 是否为住宅宽带
	SuggestScan        bool   `json:"suggest_scan"`   // 是否建议扫描 (机房为 true，家宽因几乎无网站为 false)
	CIDRCount          int    `json:"cidr_count"`
	TotalIPs           int64  `json:"total_ips"`
	ScannedIPs         int64  `json:"scanned_ips"`
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
	IPType           string   `json:"ip_type"` // "datacenter" 或 "residential"
	IsResidential    bool     `json:"is_residential"`
	SuggestScan      bool     `json:"suggest_scan"`
	Need             int      `json:"need"`
	CIDRCount        int      `json:"cidr_count"`
	TotalIPs         int64    `json:"total_ips"`
	CachedHits       int      `json:"cached_hits"`
	ScannedIPs       int64    `json:"scanned_ips"`
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
	store       storage.Store
	geoipReader *geoip2.Reader
	asnClient   asn.ASNResolver
	appConfig   *types.Config

	tasksMu sync.RWMutex
	tasks   map[string]*frontendScanTask
}

// NewProvisionService 创建供给服务实例
func NewProvisionService(
	store storage.Store,
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
		tasks:       make(map[string]*frontendScanTask),
	}
}

// GetDefaultFilter 获取默认的资产过滤偏好
func (s *ProvisionService) GetDefaultFilter() types.FilterConfig {
	if s.appConfig != nil {
		return s.appConfig.GetFilter()
	}
	return config.GetDefaultConfig().GetFilter()
}

// StreamTargets 执行渐进式目标发现：优先本地有效缓存，不足时触发实时扫描补齐
func (s *ProvisionService) StreamTargets(ctx context.Context, req ProvisionRequest, emit func(evt ProvisionEvent) error) error {
	// 1. 参数校验与补齐默认值
	targetIP := strings.TrimSpace(req.IP)
	if targetIP == "" {
		err := errors.New("missing ip parameter")
		logger.Error("❌ [扫描] 请求缺少目标 IP")
		_ = emit(ProvisionEvent{Event: "error", Data: map[string]string{"error": err.Error()}})
		return err
	}
	parsedIP := net.ParseIP(targetIP)
	if parsedIP == nil {
		err := fmt.Errorf("invalid ip address: %s", targetIP)
		logger.Error("❌ [扫描] 目标 IP 格式无效: %s", targetIP)
		_ = emit(ProvisionEvent{Event: "error", Data: map[string]string{"error": err.Error()}})
		return err
	}
	targetAddr, targetAddrErr := netip.ParseAddr(targetIP)
	if targetAddrErr == nil {
		targetAddr = targetAddr.Unmap()
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
		logger.Error("❌ [扫描] ASN 查询失败: IP=%s, error=%v", targetIP, err)
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
		// 目标 IP 所在 CIDR 必须保留并优先探测，不能因为 CIDR 起始地址
		// 的 GeoIP 与目标 IP 不同而被整段过滤掉。
		isTargetCIDR := targetAddrErr == nil && prefix.Contains(targetAddr)
		if !isTargetCIDR && s.geoipReader != nil && country != "" {
			if rec, err := s.geoipReader.Country(net.ParseIP(prefix.Addr().String())); err == nil {
				if !strings.EqualFold(rec.Country.IsoCode, country) {
					continue
				}
			}
		}
		matchedCIDRs = append(matchedCIDRs, prefix.String())
	}
	matchedCIDRs = core.PrioritizeCIDRsByIP(matchedCIDRs, targetIP)
	if len(matchedCIDRs) > 0 {
		logger.Info("🔎 [扫描] CIDR 优先级已应用: target=%s, first_cidr=%s", targetIP, matchedCIDRs[0])
	}

	var cachedTargets []*types.TargetRecord
	if !req.Fresh && s.store != nil {
		cachedTargets, _ = s.store.GetTargetsByASN(asnStr, country, req.MaxAge)
	}

	var hasCheckpoint bool
	var lastCheckpointIP string
	var checkpointedIPs int64
	if s.store != nil {
		if cps, err := s.store.GetCheckpoints(asnStr); err == nil && len(cps) > 0 {
			hasCheckpoint = true
			checkpointedIPs = core.CalculateScannedIPs(matchedCIDRs, cps)
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
			ScannedIPs:       checkpointedIPs,
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
	var resultMu sync.Mutex

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

			// 临期证书按需懒探测: 如果同 ASN 缓存记录证书剩余 < 30 天，且距离上次检测超过 10 分钟，执行即时复查
			if rec.GetRemainingDays() < 30 && time.Since(rec.LastCheckedAt) > 10*time.Minute {
				rec, _ = s.RecheckTargetCert(ctx, rec)
			}

			var certExpirePtr *time.Time
			if !rec.CertExpireAt.IsZero() {
				certExpirePtr = &rec.CertExpireAt
			}

			item := TargetItem{
				Source:          "cache",
				Domain:          rec.Domain,
				IP:              rec.IP,
				ASN:             rec.ASN,
				Country:         rec.Country,
				Stars:           rec.Stars,
				HandshakeMS:     rec.HandshakeMS,
				CertDays:        rec.GetRemainingDays(),
				CertExpireAt:    certExpirePtr,
				Tags:            rec.Tags,
				StatusCode:      rec.StatusCode,
				PageTitle:       rec.PageTitle,
				IsCDN:           rec.IsCDN,
				IsDefaultPage:   rec.IsDefaultPage,
				DefaultPageType: rec.DefaultPageType,
				IsStarred:       rec.IsStarred,
				IsDisliked:      rec.IsDisliked,
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
	if err := engine.Start(); err != nil {
		return fmt.Errorf("start scan engine: %w", err)
	}
	defer func() { _ = engine.Stop() }()

	var lastProgressTime time.Time
	var progressMu sync.Mutex
	// progress.scanned_ips 对前端展示的是整个 ASN 的累计进度，而不是本次
	// 连接建立后的增量。断点中的已完成网段和已扫描 IP 要计入初始值。
	var totalScannedIPs int64 = checkpointedIPs
	var lastProgressCIDR string
	var lastProgressIP string

	scanEvents := core.AutoScanEvents{
		OnLog: func(msg string) {
			logger.Info("[扫描] ASN=%s: %s", asnStr, msg)
		},
		OnIPScanned: func(delta int, currentCIDR string, currentIP string, currentIdx int, totalCIDRs int) {
			newTotal := atomic.AddInt64(&totalScannedIPs, int64(delta))
			progressMu.Lock()
			lastProgressCIDR = currentCIDR
			lastProgressIP = currentIP
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
		OnCandidateDiscovered: func(ip string, domain string) {
			logger.Info("🔎 扫描发现候选域名: %s (IP: %s)", domain, ip)
		},
		OnTargetFound: func(res *types.DetectionResult, count int, ip string, handshakeMs int64, statusCode int) {
			if res == nil || res.Domain == "" {
				return
			}
			resultMu.Lock()
			if seenDomains[res.Domain] {
				resultMu.Unlock()
				return
			}
			stars := core.CalculateTargetStars(res)
			if stars < req.MinStars {
				resultMu.Unlock()
				return
			}
			seenDomains[res.Domain] = true
			fromScanCount++
			resultMu.Unlock()

			rec := storage.DetectionResultToRecord(res, asnStr, country, ip, stars)
			if s.store != nil {
				if starred, err := s.store.GetTargetStarred(rec.Domain); err == nil {
					rec.IsStarred = starred
				}
				if disliked, err := s.store.GetTargetDisliked(rec.Domain); err == nil {
					rec.IsDisliked = disliked
				}
			}
			var certExpirePtr *time.Time
			if !rec.CertExpireAt.IsZero() {
				certExpirePtr = &rec.CertExpireAt
			}

			item := TargetItem{
				Source:          "scan",
				Domain:          rec.Domain,
				IP:              rec.IP,
				ASN:             rec.ASN,
				Country:         rec.Country,
				Stars:           rec.Stars,
				HandshakeMS:     rec.HandshakeMS,
				CertDays:        rec.GetRemainingDays(),
				CertExpireAt:    certExpirePtr,
				Tags:            rec.Tags,
				StatusCode:      rec.StatusCode,
				PageTitle:       rec.PageTitle,
				IsCDN:           rec.IsCDN,
				IsDefaultPage:   rec.IsDefaultPage,
				DefaultPageType: rec.DefaultPageType,
				IsStarred:       rec.IsStarred,
				IsDisliked:      rec.IsDisliked,
				CreatedAt:       rec.LastCheckedAt,
			}

			_ = emit(ProvisionEvent{Event: "target", Data: item})

			// 凑够即停，主动刹车 (全量扫描模式时不按 limit 刹车)
			if !req.ScanAll && fromCacheCount+fromScanCount >= req.Limit {
				cancelScan()
			}
		},
		OnError: func(err error) {
			logger.Error("❌ [扫描] 断点或扫描状态持久化失败: ASN=%s, error=%v", asnStr, err)
		},
	}

	filterConfig := types.FilterConfig{
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
	if scanErr != nil && !errors.Is(scanErr, core.ErrAllCompleted) && !errors.Is(scanErr, context.Canceled) {
		logger.Error("❌ [扫描] 自动扫描执行失败: ASN=%s, IP=%s, error=%v", asnStr, targetIP, scanErr)
	}

	// 最后一个进度回调可能因 300ms 节流未发送，结束前补发一次，确保前端
	// 在失败或中断时看到的累计数字与已保存断点一致。
	progressMu.Lock()
	finalCIDR := lastProgressCIDR
	finalIP := lastProgressIP
	progressMu.Unlock()
	_ = emit(ProvisionEvent{
		Event: "progress",
		Data: ProgressEventData{
			ScannedIPs:  atomic.LoadInt64(&totalScannedIPs),
			CurrentCIDR: finalCIDR,
			CurrentIP:   finalIP,
		},
	})

	reason := "scan_exhausted"
	if fromCacheCount+fromScanCount >= req.Limit {
		reason = "limit_hit"
	} else if scanCtx.Err() == context.Canceled && ctx.Err() == nil {
		reason = "limit_hit"
	} else if ctx.Err() != nil {
		reason = "cancelled"
	} else if errors.Is(scanErr, core.ErrAllCompleted) {
		// 所有网段已经在之前完成，不属于本次扫描失败。
		reason = "scan_exhausted"
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
	var targetAddr netip.Addr
	var targetAddrValid bool
	var prefixes []string
	var matchedCIDRs []string
	var cidrCount int
	var totalIPs int64
	var hasCheckpoint bool
	var lastCheckpointIP string
	var checkpointedIPs int64
	var completedCIDRCount int

	var asnNum int
	// 1. 若提供了目标 IP，智能解析其 ASN 与国家及网段
	if targetIP != "" {
		if parsedIP := net.ParseIP(targetIP); parsedIP != nil {
			if addr, err := netip.ParseAddr(targetIP); err == nil {
				targetAddr = addr.Unmap()
				targetAddrValid = true
			}
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
		isTargetCIDR := targetAddrValid && prefix.Contains(targetAddr)
		if !isTargetCIDR && s.geoipReader != nil && targetCountry != "" {
			if rec, err := s.geoipReader.Country(net.ParseIP(prefix.Addr().String())); err == nil {
				if !strings.EqualFold(rec.Country.IsoCode, targetCountry) {
					continue
				}
			}
		}
		matchedCIDRs = append(matchedCIDRs, prefix.String())
	}
	matchedCIDRs = core.PrioritizeCIDRsByIP(matchedCIDRs, targetIP)
	cidrCount = len(matchedCIDRs)
	if cidrCount > 0 {
		totalIPs = core.CalculateTotalIPs(matchedCIDRs)
	}

	if targetASN != "" && s.store != nil {
		if cps, err := s.store.GetCheckpoints(targetASN); err == nil && len(cps) > 0 {
			hasCheckpoint = true
			checkpointedIPs = core.CalculateScannedIPs(matchedCIDRs, cps)
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

	// 2. 多级候选集智能召回 (同 ASN -> 同国家 -> 全球高星)，避免大表全量加载与内存爆满
	candidateMap := make(map[string]*types.TargetRecord)
	var candidateList []*types.TargetRecord

	addCandidate := func(rec *types.TargetRecord) {
		if rec == nil || rec.Domain == "" || !rec.IsActive {
			return
		}
		if _, exists := candidateMap[rec.Domain]; !exists {
			candidateMap[rec.Domain] = rec
			candidateList = append(candidateList, rec)
		}
	}

	// 2.1 同 ASN 候选优先召回 (最高置顶优先级)
	if targetASN != "" {
		if asnRecords, err := s.store.GetTargetsByASN(targetASN, "", 0); err == nil {
			for _, rec := range asnRecords {
				addCandidate(rec)
			}
		}
	}

	// 2.2 同国家优质候选召回 (次高优先级)
	isActive := true
	if targetCountry != "" {
		countryOpts := types.TargetQueryOptions{
			Country:  targetCountry,
			MinStars: req.MinStars,
			IsActive: &isActive,
			SortBy:   "stars_desc",
			Page:     1,
			PageSize: 100,
		}
		if countryRecords, _, err := s.store.QueryTargets(countryOpts); err == nil {
			for _, rec := range countryRecords {
				addCandidate(rec)
			}
		}
	}

	// 2.3 全球高星优质候选底池
	globalOpts := types.TargetQueryOptions{
		MinStars: req.MinStars,
		IsActive: &isActive,
		SortBy:   "stars_desc",
		Page:     1,
		PageSize: 100,
	}
	if globalRecords, _, err := s.store.QueryTargets(globalOpts); err == nil {
		for _, rec := range globalRecords {
			addCandidate(rec)
		}
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
		ScannedIPs:         checkpointedIPs,
		HasCheckpoint:      hasCheckpoint,
		LastCheckpointIP:   lastCheckpointIP,
		CompletedCIDRCount: completedCIDRCount,
	}

	var ranked []RankedTargetItem
	targetASNNorm := strings.ToUpper(strings.TrimPrefix(targetASN, "AS"))

	for _, rec := range candidateList {
		if req.MinStars > 0 && rec.Stars < req.MinStars {
			continue
		}

		dLower := strings.ToLower(rec.Domain)
		if req.RequireNoCN && (strings.HasSuffix(dLower, ".cn") || strings.Contains(dLower, ".edu.cn") || strings.Contains(dLower, ".gov.cn")) {
			continue
		}

		recASNNorm := strings.ToUpper(strings.TrimPrefix(rec.ASN, "AS"))
		isSameASN := (targetASNNorm != "" && recASNNorm != "" && targetASNNorm == recASNNorm)
		isSameCountry := (targetCountry != "" && strings.EqualFold(rec.Country, targetCountry))

		var certExpirePtr *time.Time
		if !rec.CertExpireAt.IsZero() {
			certExpirePtr = &rec.CertExpireAt
		}

		item := TargetItem{
			Source:          "cache",
			Domain:          rec.Domain,
			IP:              rec.IP,
			ASN:             rec.ASN,
			Country:         rec.Country,
			Stars:           rec.Stars,
			HandshakeMS:     rec.HandshakeMS,
			CertDays:        rec.GetRemainingDays(),
			CertExpireAt:    certExpirePtr,
			Tags:            rec.Tags,
			StatusCode:      rec.StatusCode,
			PageTitle:       rec.PageTitle,
			IsCDN:           rec.IsCDN,
			IsDefaultPage:   rec.IsDefaultPage,
			DefaultPageType: rec.DefaultPageType,
			IsStarred:       rec.IsStarred,
			IsDisliked:      rec.IsDisliked,
			CreatedAt:       rec.LastCheckedAt,
		}

		// 3. 动态智能加权打分模型
		score := 0
		matchLevel := "global"

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
		if rec.GetRemainingDays() >= 30 {
			score += 20
		}

		// 疑似未自动续期惩罚 (若进入30天续期窗口但仍未自动续期，扣除推荐权重，避免高危临期域名置顶)
		if rec.HasTag(types.TagCertRenewDelayed) {
			score -= 100
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

	// 4. 高效 O(N log N) 排序
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].IsDisliked != ranked[j].IsDisliked {
			return !ranked[i].IsDisliked
		}
		if ranked[i].IsStarred != ranked[j].IsStarred {
			return ranked[i].IsStarred
		}
		return ranked[i].Score > ranked[j].Score
	})

	// 5. 对最具潜力的前 N 个同 ASN 临期候选资产执行按需懒探测（并发复核，限制最长耗时）
	topCheckCount := req.Limit
	if topCheckCount > len(ranked) {
		topCheckCount = len(ranked)
	}

	var recheckWg sync.WaitGroup
	var recheckMu sync.Mutex
	recheckedAny := false

	for i := 0; i < topCheckCount; i++ {
		rItem := &ranked[i]
		if rItem.MatchLevel == "same_asn" && rItem.CertDays < 30 && time.Since(rItem.CreatedAt) > 10*time.Minute {
			recheckWg.Add(1)
			go func(itemPtr *RankedTargetItem) {
				defer recheckWg.Done()
				targetRec := &types.TargetRecord{
					Domain:        itemPtr.Domain,
					IP:            itemPtr.IP,
					ASN:           itemPtr.ASN,
					Country:       itemPtr.Country,
					Port:          443,
					HandshakeMS:   itemPtr.HandshakeMS,
					CertDays:      itemPtr.CertDays,
					Tags:          itemPtr.Tags,
					LastCheckedAt: itemPtr.CreatedAt,
				}
				if itemPtr.CertExpireAt != nil {
					targetRec.CertExpireAt = *itemPtr.CertExpireAt
				}

				updatedRec, changed := s.RecheckTargetCert(ctx, targetRec)
				if changed && updatedRec != nil {
					recheckMu.Lock()
					defer recheckMu.Unlock()
					recheckedAny = true

					itemPtr.CertDays = updatedRec.GetRemainingDays()
					if !updatedRec.CertExpireAt.IsZero() {
						itemPtr.CertExpireAt = &updatedRec.CertExpireAt
					}
					itemPtr.Tags = updatedRec.Tags
					itemPtr.HandshakeMS = updatedRec.HandshakeMS

					if updatedRec.HasTag(types.TagCertRenewDelayed) && !targetRec.HasTag(types.TagCertRenewDelayed) {
						itemPtr.Score -= 100
					} else if !updatedRec.HasTag(types.TagCertRenewDelayed) && targetRec.HasTag(types.TagCertRenewDelayed) {
						itemPtr.Score += 100
					}
					if itemPtr.CertDays >= 30 && targetRec.CertDays < 30 {
						itemPtr.Score += 20
					}
				}
			}(rItem)
		}
	}
	recheckWg.Wait()

	if recheckedAny {
		sort.Slice(ranked, func(i, j int) bool {
			if ranked[i].IsDisliked != ranked[j].IsDisliked {
				return !ranked[i].IsDisliked
			}
			if ranked[i].IsStarred != ranked[j].IsStarred {
				return ranked[i].IsStarred
			}
			return ranked[i].Score > ranked[j].Score
		})
	}

	// 6. 截取 limit 条数
	if len(ranked) > req.Limit {
		ranked = ranked[:req.Limit]
	}

	return ranked, summary, nil
}

// RecheckTargetCert 对目标资产执行快速 TLS 握手复查证书有效性与续期状态
// 返回更新后的 TargetRecord 以及是否发生了实质性状态变化 (renewed/flagged)
func (s *ProvisionService) RecheckTargetCert(ctx context.Context, target *types.TargetRecord) (*types.TargetRecord, bool) {
	if target == nil || target.Domain == "" {
		return target, false
	}

	port := target.Port
	if port <= 0 {
		port = 443
	}
	host := target.IP
	if host == "" {
		host = target.Domain
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	// 设置快速超时的独立探测 Context (最长 2 秒，避免阻塞外部请求)
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	tcpConn, err := dialer.DialContext(probeCtx, "tcp", address)
	if err != nil {
		return target, false
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}

	tlsCfg := &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	defer tlsConn.Close()

	start := time.Now()
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		return target, false
	}
	handshakeMS := time.Since(start).Milliseconds()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return target, false
	}

	leaf := state.PeerCertificates[0]
	remoteExpire := leaf.NotAfter
	remoteDays := int(time.Until(remoteExpire).Hours() / 24)
	if remoteDays < 0 {
		remoteDays = 0
	}

	now := time.Now()
	target.LastCheckedAt = now
	target.HandshakeMS = handshakeMS

	// 分支判断:
	// 1. 如果远端证书已续订 (到期时间比原有记录更晚，或剩余天数恢复至 30 天以上)
	if (!target.CertExpireAt.IsZero() && remoteExpire.After(target.CertExpireAt.Add(24*time.Hour))) || remoteDays >= 30 {
		target.CertExpireAt = remoteExpire
		target.CertDays = remoteDays
		target.RemoveTag(types.TagCertRenewDelayed)
		if s.store != nil {
			_ = s.store.UpdateTargetCertRenewal(target.Domain, remoteExpire, remoteDays, target.Tags, handshakeMS)
		}
		logger.Info("🔄 [证书续期检测] 目标 %s 证书已成功续期！剩余天数: %d天", target.Domain, remoteDays)
		return target, true
	}

	// 2. 远端证书未变，且剩余天数依然 < 30 天 (疑似未自动续期)
	target.CertExpireAt = remoteExpire
	target.CertDays = remoteDays
	target.AddTag(types.TagCertRenewDelayed)
	if s.store != nil {
		_ = s.store.UpdateTargetCertRenewal(target.Domain, remoteExpire, remoteDays, target.Tags, handshakeMS)
	}
	logger.Warn("⚠️ [证书续期检测] 目标 %s 处于临期窗口 (<30天)，且远端尚未自动续期 (剩余 %d天)，已标记", target.Domain, remoteDays)
	return target, true
}

// CheckSingleDomain 在线即时检测单个域名/IP 并持久化至资产库
func (s *ProvisionService) CheckSingleDomain(ctx context.Context, domain, manualIP string) (*types.TargetRecord, error) {
	d := strings.TrimSpace(domain)
	if d == "" {
		return nil, errors.New("domain cannot be empty")
	}
	manualIP = strings.TrimSpace(manualIP)
	if ctx == nil {
		ctx = context.Background()
	}

	// 单域名复核使用独立的连接管理器，并设置服务端兜底截止时间。
	// 前台全量扫描即使占满网络资源，也不能让资产管理页面永久等待。
	probeTimeout := 30 * time.Second
	if s.appConfig != nil && s.appConfig.Concurrency.CheckTimeout > 0 {
		probeTimeout = s.appConfig.Concurrency.CheckTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	connMgr := network.NewConnectionManager(s.appConfig)
	pipeline := core.NewPipeline(connMgr, s.appConfig)
	res, err := pipeline.ExecuteWithTargetIP(probeCtx, d, manualIP)
	if err != nil {
		return nil, fmt.Errorf("pipeline execution failed: %w", err)
	}
	if res.Error != nil {
		return nil, fmt.Errorf("baseline verification failed: %w", res.Error)
	}
	if !res.Suitable {
		return nil, errors.New("target domain is not suitable for REALITY")
	}

	var ipStr, asnStr, countryStr string
	if manualIP != "" && net.ParseIP(manualIP) != nil {
		ipStr = manualIP
	} else if res.Location != nil && res.Location.IPAddress != "" {
		ipStr = res.Location.IPAddress
	}

	if ipStr == "" {
		lookupCtx, cancelLookup := context.WithTimeout(probeCtx, 2*time.Second)
		ips, err := net.DefaultResolver.LookupIPAddr(lookupCtx, d)
		cancelLookup()
		if err == nil && len(ips) > 0 {
			ipStr = ips[0].String()
		}
	}

	if ipStr != "" {
		if parsed := net.ParseIP(ipStr); parsed != nil {
			if s.geoipReader != nil {
				if rec, err := s.geoipReader.Country(parsed); err == nil {
					countryStr = strings.ToUpper(rec.Country.IsoCode)
				}
			}
			if s.asnClient != nil {
				if asnNum, _, err := s.asnClient.PrefixesForIP(probeCtx, ipStr); err == nil && asnNum > 0 {
					asnStr = fmt.Sprintf("AS%d", asnNum)
				}
			}
		}
	}

	if countryStr == "" && res.Location != nil && res.Location.Country != "" {
		countryStr = res.Location.Country
	}
	if asnStr == "" && res.Location != nil && res.Location.ASN != "" {
		asnStr = res.Location.ASN
	}

	stars := core.CalculateTargetStars(res)
	rec := storage.DetectionResultToRecord(res, asnStr, countryStr, ipStr, stars)
	if rec == nil {
		return nil, errors.New("failed to convert detection result to record")
	}

	if s.store != nil {
		if starred, err := s.store.GetTargetStarred(rec.Domain); err == nil {
			rec.IsStarred = starred
		}
		if disliked, err := s.store.GetTargetDisliked(rec.Domain); err == nil {
			rec.IsDisliked = disliked
		}
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

// UpdateTargetStarred 更新资产的用户收藏状态
func (s *ProvisionService) UpdateTargetStarred(domain string, starred bool) error {
	if s.store == nil {
		return errors.New("store not available")
	}
	return s.store.UpdateTargetStarred(domain, starred)
}

// UpdateTargetDisliked 更新资产的用户差评状态。
func (s *ProvisionService) UpdateTargetDisliked(domain string, disliked bool) error {
	if s.store == nil {
		return errors.New("store not available")
	}
	return s.store.UpdateTargetDisliked(domain, disliked)
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

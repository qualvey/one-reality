package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/adaptive"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

var (
	// ErrAllCompleted 表示该任务此前已全部扫描完成
	ErrAllCompleted = errors.New("all cidrs completed in previous scan")
	// ErrNoCIDRsProvided 表示未提供待扫描网段
	ErrNoCIDRsProvided = errors.New("no CIDRs provided for scanning")
)

// AutoScanConfig 自动探测与网络扫描核心参数
type AutoScanConfig struct {
	CIDRs          []string
	MaxTargets     int
	CheckAll       bool
	Filter         types.FilterConfig
	ASN            string
	Country        string
	InitialResults []*types.DetectionResult
	Profile        PipelineProfile // 可选指定流水线编排画像 (如 ProfileFast 吞吐优先)
	Verbose        bool
}

// AutoScanEvents 外部订阅扫描过程的事件回调集合，完全解耦 UI 与进度渲染
type AutoScanEvents struct {
	// OnIPScanned 扫描到 IP 时的增量回调 (增量数, 当前网段, 当前扫描IP, 网段索引1-based, 总网段数)
	OnIPScanned func(delta int, currentCIDR string, currentIP string, currentIdx int, totalCIDRs int)
	// OnScanRecord 每次单个 IP 探活完成时回调（无论成功或失败）
	OnScanRecord func(probe *scanner.ProbeResult)
	// OnCandidateRejected 候选域名未能通过阶段一基线或阶段二过滤时回调
	OnCandidateRejected func(ip string, domain string, reason string)
	// OnCandidateDiscovered 从证书中发现新域名候选时回调（适用性检测前）
	OnCandidateDiscovered func(ip string, domain string)
	// OnAdaptiveAdjust 自适应限流中枢做出并发收敛或爬升决策时通知
	OnAdaptiveAdjust func(stats adaptive.LimiterStats)
	// OnTargetFound 发现并判定为符合条件的目标时回调
	OnTargetFound func(res *types.DetectionResult, count int, ip string, handshakeMs int64, statusCode int)
	// OnLimitHit 达到指定目标数量限制时回调
	OnLimitHit func(maxTargets int)
	// OnCIDRScanStart 开始扫描某一网段时的通知
	OnCIDRScanStart func(currentIdx int, totalCIDRs int, cidr string, resumeIP string)
	// OnLog 一般信息日志通知
	OnLog func(msg string)
	// OnError 持久化或断点操作失败时通知调用方
	OnError func(err error)
}

// AutoScanResult 扫描完成或中断返回的聚合业务结果
type AutoScanResult struct {
	RawCandidatePool []*types.DetectionResult
	SuitableResults  []*types.DetectionResult
	TotalIPs         int64
	RemainingIPs     int64
	IsInterrupted    bool
	AllCompleted     bool
}

// AutoScanner 核心自动扫描调度器
type AutoScanner struct {
	engine        *Engine
	store         storage.Store
	scannerEngine *scanner.Scanner
	config        AutoScanConfig
	events        AutoScanEvents

	taskKey        string
	cidrs          []string
	checkpointsMap map[string]*storage.CheckpointRecord

	mu               sync.Mutex
	domainSet        map[string]bool
	rawCandidatePool []*types.DetectionResult
	suitableResults  []*types.DetectionResult

	limiter adaptive.RateLimiter
	profile adaptive.HardwareProfile

	dbWriteMu          sync.Mutex
	persistenceErrOnce sync.Once
}

// NewAutoScanner 创建纯净的自动扫描调度器（纯内存组装，无副作用）
func NewAutoScanner(
	engine *Engine,
	store storage.Store,
	scannerEngine *scanner.Scanner,
	cfg AutoScanConfig,
	events AutoScanEvents,
) *AutoScanner {
	taskKey := ""
	if cfg.ASN != "" && cfg.Country != "" {
		taskKey = fmt.Sprintf("%s_%s", cfg.ASN, cfg.Country)
	}

	cidrsCopy := make([]string, len(cfg.CIDRs))
	copy(cidrsCopy, cfg.CIDRs)

	profile := adaptive.DetectHardwareProfile()
	if cfg.Filter.ScanThreads > 0 {
		profile.InitialConcurrency = cfg.Filter.ScanThreads
		if profile.InitialConcurrency > profile.MaxConcurrency {
			profile.MaxConcurrency = profile.InitialConcurrency
		}
	}
	limiter := adaptive.NewAdaptiveLimiter(profile, nil)

	s := &AutoScanner{
		engine:           engine,
		store:            store,
		scannerEngine:    scannerEngine,
		config:           cfg,
		events:           events,
		taskKey:          taskKey,
		cidrs:            cidrsCopy,
		domainSet:        make(map[string]bool),
		rawCandidatePool: make([]*types.DetectionResult, 0),
		suitableResults:  make([]*types.DetectionResult, 0),
		limiter:          limiter,
		profile:          profile,
	}

	// 预加载传入的历史有效初始目标
	for _, res := range cfg.InitialResults {
		if res != nil && res.Domain != "" {
			s.domainSet[res.Domain] = true
			s.suitableResults = append(s.suitableResults, res)
			s.rawCandidatePool = append(s.rawCandidatePool, res)
		}
	}

	if cfg.Profile != "" && engine != nil {
		engine.SetProfile(cfg.Profile)
	}

	return s
}

// Run 执行完整的扫描与并发检测流水线
func (s *AutoScanner) Run(parentCtx context.Context) (*AutoScanResult, error) {
	if len(s.cidrs) == 0 {
		return nil, ErrNoCIDRsProvided
	}

	grandTotalIPCount := CalculateTotalIPs(s.cidrs)

	// 1. 检查断点续传状态
	if s.config.CheckAll && s.store != nil && s.taskKey != "" && !s.config.Filter.NoResume {
		checkpointsMap, _ := s.store.GetCheckpoints(s.taskKey)
		if len(checkpointsMap) > 0 {
			var remainingCIDRs []string
			var skippedCompletedCount int
			var resumedPartiallyCount int

			for _, c := range s.cidrs {
				cp := checkpointsMap[c]
				if cp != nil && cp.Completed {
					skippedCompletedCount++
				} else {
					if cp != nil && cp.LastIP != "" {
						resumedPartiallyCount++
					}
					remainingCIDRs = append(remainingCIDRs, c)
				}
			}

			if skippedCompletedCount > 0 || resumedPartiallyCount > 0 {
				if len(remainingCIDRs) == 0 {
					return &AutoScanResult{
						TotalIPs:     grandTotalIPCount,
						RemainingIPs: 0,
						AllCompleted: true,
					}, ErrAllCompleted
				}
				if s.events.OnLog != nil {
					if resumedPartiallyCount > 0 {
						s.events.OnLog(fmt.Sprintf("🔄 发现精确 IP 断点续传记录 (%s)：跳过 %d 个已完成网段，从剩余 %d 个网段（含 IP 续传网段）继续...",
							s.taskKey, skippedCompletedCount, len(remainingCIDRs)))
					} else {
						s.events.OnLog(fmt.Sprintf("🔄 发现断点续传记录 (%s)：自动跳过已完成的 %d 个网段，继续断点扫描剩余 %d 个网段...",
							s.taskKey, skippedCompletedCount, len(remainingCIDRs)))
					}
				}
				s.cidrs = remainingCIDRs
			}
			s.checkpointsMap = checkpointsMap
		}
	}

	remainingIPCount := CalculateRemainingIPs(s.cidrs, s.checkpointsMap)

	// 2. 构造流水线并发通道与任务追踪
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	if s.limiter != nil {
		defer s.limiter.Stop()
		if s.events.OnAdaptiveAdjust != nil {
			go func() {
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				var lastReason string
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						stats := s.limiter.Stats()
						if stats.LastAction != adaptive.ActionHold && stats.LastActionReason != lastReason {
							lastReason = stats.LastActionReason
							s.events.OnAdaptiveAdjust(stats)
						}
					}
				}
			}()
		}
	}

	scanResultChan := make(chan *scanner.ScanResult, 20000)
	var taskWg sync.WaitGroup
	var workerPoolWg sync.WaitGroup

	// 启动 Worker 协程池
	concurrency := 30
	if s.config.Filter.ScanThreads > 500 {
		concurrency = 60
	}

	for i := 0; i < concurrency; i++ {
		workerPoolWg.Add(1)
		go func() {
			defer workerPoolWg.Done()
			for scanRes := range scanResultChan {
				s.processCandidate(ctx, scanRes, cancel, &taskWg)
			}
		}()
	}

	// 3. 逐个流式扫描各个 CIDR
	totalCIDRs := len(s.cidrs)
CIDRLoop:
	for idx, cidr := range s.cidrs {
		select {
		case <-ctx.Done():
			break CIDRLoop
		default:
		}

		if s.hasHitTargetLimit() {
			break CIDRLoop
		}

		s.scanSingleCIDR(ctx, cidr, idx+1, totalCIDRs, scanResultChan, &taskWg)
	}

	// 4. 等待所有在途检测任务完成并回收 Worker
	taskWg.Wait()
	close(scanResultChan)
	workerPoolWg.Wait()

	// 5. 组装返回结果与断点收尾
	isInterrupted := parentCtx.Err() != nil

	if !isInterrupted && s.config.CheckAll && s.store != nil && s.taskKey != "" {
		_ = s.store.ClearCheckpoints(s.taskKey)
	}

	// 最终策略过滤与裁剪
	s.mu.Lock()
	filteredSuitable := FilterPool(s.suitableResults, s.config.Filter)
	if !s.config.CheckAll && s.config.MaxTargets > 0 && len(filteredSuitable) > s.config.MaxTargets {
		filteredSuitable = filteredSuitable[:s.config.MaxTargets]
	}
	rawCopy := make([]*types.DetectionResult, len(s.rawCandidatePool))
	copy(rawCopy, s.rawCandidatePool)
	s.mu.Unlock()

	return &AutoScanResult{
		RawCandidatePool: rawCopy,
		SuitableResults:  filteredSuitable,
		TotalIPs:         grandTotalIPCount,
		RemainingIPs:     remainingIPCount,
		IsInterrupted:    isInterrupted,
		AllCompleted:     false,
	}, nil
}

func (s *AutoScanner) processCandidate(ctx context.Context, scanRes *scanner.ScanResult, cancel context.CancelFunc, taskWg *sync.WaitGroup) {
	defer taskWg.Done()
	if scanRes == nil || s.hasHitTargetLimit() {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	d := strings.TrimSpace(strings.ToLower(scanRes.CertDomain))
	if strings.HasPrefix(d, "*.") && len(d) > 2 {
		d = strings.TrimPrefix(d, "*.")
	}
	if d == "" {
		return
	}
	res, err := s.engine.CheckDomain(ctx, d)

	if s.hasHitTargetLimit() {
		return
	}

	// 阶段一：硬性技术基线检验
	if err == nil && res != nil && res.Suitable && res.Error == nil {
		stars := CalculateTargetStars(res)

		s.mu.Lock()
		s.rawCandidatePool = append(s.rawCandidatePool, res)
		s.mu.Unlock()

		// 自动持久化资产库 (按 ASN/国家 归档)
		if s.store != nil {
			rec := storage.DetectionResultToRecord(res, s.config.ASN, s.config.Country, scanRes.IP, stars)
			if err := s.store.UpsertTarget(rec); err != nil {
				s.reportPersistenceError(fmt.Errorf("写入目标 %q (IP %s) 失败: %w", rec.Domain, rec.IP, err))
			}
		}

		// 阶段二：进阶偏好过滤
		passed, rejectReason := FilterTarget(res, s.config.Filter)
		if passed {
			s.mu.Lock()
			s.suitableResults = append(s.suitableResults, res)
			suitableCount := len(s.suitableResults)
			hitLimit := !s.config.CheckAll && s.config.MaxTargets > 0 && suitableCount >= s.config.MaxTargets
			s.mu.Unlock()

			var handshakeMs int64 = 0
			if res.TLS != nil {
				handshakeMs = res.TLS.HandshakeTime.Milliseconds()
			}
			var statusCode int = 0
			if res.Network != nil {
				statusCode = res.Network.StatusCode
			}

			if s.events.OnTargetFound != nil {
				s.events.OnTargetFound(res, suitableCount, scanRes.IP, handshakeMs, statusCode)
			}

			if hitLimit {
				if s.events.OnLimitHit != nil {
					s.events.OnLimitHit(s.config.MaxTargets)
				}
				cancel()
			}
		} else if s.events.OnCandidateRejected != nil {
			s.events.OnCandidateRejected(scanRes.IP, d, rejectReason)
		}
	} else if s.events.OnCandidateRejected != nil {
		reason := "未通过硬性技术基线"
		if res != nil && res.Error != nil {
			reason = res.Error.Error()
		} else if err != nil {
			reason = err.Error()
		} else if res != nil && res.Summary != nil && len(res.Summary.Recommendations) > 0 {
			reason = strings.Join(res.Summary.Recommendations, "; ")
		}
		s.events.OnCandidateRejected(scanRes.IP, d, reason)
	}
}

func (s *AutoScanner) scanSingleCIDR(
	ctx context.Context,
	cidr string,
	currentIdx int,
	totalCIDRs int,
	scanResultChan chan *scanner.ScanResult,
	taskWg *sync.WaitGroup,
) {
	startIP := ""
	if cp := s.checkpointsMap[cidr]; cp != nil && !cp.Completed {
		startIP = cp.LastIP
	}

	if s.events.OnCIDRScanStart != nil {
		s.events.OnCIDRScanStart(currentIdx, totalCIDRs, cidr, startIP)
	}

	subChan := make(chan *scanner.ScanResult, 20000)

	var pipeWg sync.WaitGroup
	pipeWg.Add(1)
	go func() {
		defer pipeWg.Done()
		for res := range subChan {
			if res == nil {
				continue
			}

			// 收集该证书挖掘出的全部候选域名（优先使用 CertDomains 完整列表，回退单个 CertDomain）
			domains := res.CertDomains
			if len(domains) == 0 && res.CertDomain != "" {
				domains = []string{res.CertDomain}
			}

			for _, candidateDomain := range domains {
				candidateDomain = strings.TrimSpace(candidateDomain)
				if candidateDomain == "" {
					continue
				}

				s.mu.Lock()
				alreadySeen := s.domainSet[candidateDomain]
				if !alreadySeen {
					s.domainSet[candidateDomain] = true
				}
				s.mu.Unlock()

				if alreadySeen {
					continue
				}

				if s.events.OnCandidateDiscovered != nil {
					s.events.OnCandidateDiscovered(res.IP, candidateDomain)
				}

				// 早期过滤：如果启用了排除国内站点策略，立刻拦截
				if s.config.Filter.RequireNoCN {
					dLower := strings.ToLower(candidateDomain)
					if strings.HasSuffix(dLower, ".cn") ||
						strings.Contains(dLower, ".edu.cn") ||
						strings.Contains(dLower, ".gov.cn") {
						continue
					}
				}

				taskWg.Add(1)
				// 浅拷贝对象，为当前特定 SAN 域名派生独立评估任务
				item := *res
				item.CertDomain = candidateDomain
				select {
				case scanResultChan <- &item:
				case <-ctx.Done():
					taskWg.Done()
					return
				}
			}
		}
	}()

	currentCIDR := cidr
	var lastScannedIP string = startIP
	var lastMaxAddr netip.Addr
	if startIP != "" {
		lastMaxAddr, _ = netip.ParseAddr(startIP)
	}
	var lastIPMu sync.Mutex
	var lastSaveTime time.Time
	var lastSaveIPCount int

	threads := s.config.Filter.ScanThreads
	if threads <= 0 {
		threads = s.profile.MaxConcurrency
	}
	timeout := s.config.Filter.ScanTimeout
	if timeout <= 0 {
		timeout = 3
	}

	s.scannerEngine.ScanCIDRStreamAdaptive(
		ctx,
		cidr,
		startIP,
		443,
		threads,
		timeout,
		false,
		s.limiter,
		subChan,
		func(n int, ip string) {
			if s.events.OnIPScanned != nil {
				s.events.OnIPScanned(n, currentCIDR, ip, currentIdx, totalCIDRs)
			}

			lastIPMu.Lock()
			if parsedIP, err := netip.ParseAddr(ip); err == nil {
				if !lastMaxAddr.IsValid() || parsedIP.Compare(lastMaxAddr) > 0 {
					lastMaxAddr = parsedIP
					lastScannedIP = ip
				}
			}
			lastSaveIPCount += n
			now := time.Now()
			// 节流断点保存
			if s.config.CheckAll && s.store != nil && s.taskKey != "" && (now.Sub(lastSaveTime) > time.Second || lastSaveIPCount >= 500) {
				lastSaveTime = now
				lastSaveIPCount = 0
				ipToSave := lastScannedIP
				s.recordCheckpointSafe(s.taskKey, currentCIDR, ipToSave, false)
			}
			lastIPMu.Unlock()
		},
		func(probe *scanner.ProbeResult) {
			if s.events.OnScanRecord != nil {
				s.events.OnScanRecord(probe)
			}
		},
	)

	close(subChan)
	pipeWg.Wait()

	if ctx.Err() == nil && s.config.CheckAll && s.store != nil && s.taskKey != "" {
		s.recordCheckpointSafe(s.taskKey, cidr, lastScannedIP, true)
	} else if ctx.Err() != nil && s.config.CheckAll && s.store != nil && s.taskKey != "" && lastScannedIP != "" {
		s.recordCheckpointSafe(s.taskKey, cidr, lastScannedIP, false)
	}
}

func (s *AutoScanner) recordCheckpointSafe(taskKey, cidr, ip string, completed bool) {
	s.dbWriteMu.Lock()
	defer s.dbWriteMu.Unlock()
	if s.store != nil {
		if err := s.store.RecordCheckpoint(taskKey, cidr, ip, completed); err != nil {
			s.reportPersistenceError(fmt.Errorf("保存扫描断点 %s %s 失败: %w", taskKey, cidr, err))
		}
	}
}

func (s *AutoScanner) reportPersistenceError(err error) {
	if s.events.OnError == nil {
		return
	}
	s.persistenceErrOnce.Do(func() {
		s.events.OnError(err)
	})
}

func (s *AutoScanner) hasHitTargetLimit() bool {
	if s.config.CheckAll || s.config.MaxTargets <= 0 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.suitableResults) >= s.config.MaxTargets
}

// CalculateTotalIPs 计算一组 CIDR 或单 IP 的总数量（支持 IPv4 和 IPv6，支持去重/越界大数）
func CalculateTotalIPs(cidrs []string) int64 {
	return CalculateRemainingIPs(cidrs, nil)
}

// CalculateScannedIPs 根据断点计算已经完成探测的 IP 数量，用于恢复后的累计进度展示。
func CalculateScannedIPs(cidrs []string, checkpoints map[string]*storage.CheckpointRecord) int64 {
	total := CalculateTotalIPs(cidrs)
	remaining := CalculateRemainingIPs(cidrs, checkpoints)
	if remaining >= total {
		return 0
	}
	return total - remaining
}

// CalculateRemainingIPs 计算扣除已完成/部分完成断点网段后的剩余待扫描 IP 理论总数
func CalculateRemainingIPs(cidrs []string, checkpoints map[string]*storage.CheckpointRecord) int64 {
	var total int64

	for _, raw := range cidrs {
		cp := checkpoints[raw]
		if cp != nil && cp.Completed {
			continue // 已完成的网段跳过
		}

		p, err := netip.ParsePrefix(raw)
		if err != nil {
			if ip := net.ParseIP(raw); ip != nil {
				if cp == nil || cp.LastIP == "" {
					total += 1
				}
			}
			continue
		}

		p = p.Masked()
		addr := p.Addr()

		if cp != nil && cp.LastIP != "" {
			if startAddr, err := netip.ParseAddr(cp.LastIP); err == nil && p.Contains(startAddr) {
				addr = startAddr.Next()
			}
		}

		if !p.Contains(addr) {
			continue
		}

		if addr.Is4() {
			startVal := ipv4ToUint32(addr.As4())
			lastVal := ipv4ToUint32(p.Addr().As4()) + (uint32(1) << (32 - p.Bits())) - 1
			if lastVal >= startVal {
				total += int64(lastVal - startVal + 1)
			}
		} else {
			ones := p.Bits()
			hostBits := 128 - ones
			if hostBits < 62 {
				total += int64(1) << hostBits
			}
		}
	}
	return total
}

func ipv4ToUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

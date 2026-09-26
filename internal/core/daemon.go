package core

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	asnclient "RealityChecker/internal/asn"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"

	"github.com/oschwald/geoip2-golang"
)

// DaemonConfig 24小时全天候 ASN 全网扫描调度引擎配置
type DaemonConfig struct {
	StorePath         string
	CountryDBPath     string
	ScanThreads       int
	Timeout           time.Duration
	IPv4Only          bool
	IPv6Only          bool
	HighPriorityRatio float64 // 热门高优池调度配比 (默认 0.70 即 70%)
	CycleInterval     time.Duration
	MaxTargetsPerASN  int
	SingleASN         int    // 如果 > 0 则仅持续扫描此特定 ASN
	CountryFilter     string // 可选指定国家过滤 (如 US, HK, JP, DE)
	Continuous        bool   // 完成一整轮后是否自动重置 pending 开启下一轮 (默认 true)
}

// DefaultDaemonConfig 默认守护进程配置
func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		StorePath:         "data/reality_targets.db",
		CountryDBPath:     "data/Country.mmdb",
		ScanThreads:       500,
		Timeout:           3 * time.Second,
		IPv4Only:          true,
		IPv6Only:          false,
		HighPriorityRatio: 0.70,
		CycleInterval:     10 * time.Second,
		MaxTargetsPerASN:  0, // 0 = 扫完全网段
		Continuous:        true,
	}
}

// DaemonEvents 守护调度引擎生命周期事件回调
type DaemonEvents struct {
	OnLog         func(msg string)
	OnASNStart    func(asn *types.ASNRecord, cidrCount int, totalIPs int64)
	OnASNComplete func(asn *types.ASNRecord, foundTargets int, duration time.Duration)
	OnTargetFound func(target *types.TargetRecord)
	OnError       func(err error)
}

// DaemonScheduler 全网 24小时无人值守 ASN 扫描调度中枢
type DaemonScheduler struct {
	engine        *Engine
	store         *storage.TargetStore
	scannerEngine *scanner.Scanner
	asnClient     *asnclient.Client
	geoipReader   *geoip2.Reader
	config        DaemonConfig
	events        DaemonEvents
	randSource    *rand.Rand
}

// NewDaemonScheduler 创建守护调度引擎
func NewDaemonScheduler(
	engine *Engine,
	store *storage.TargetStore,
	scannerEngine *scanner.Scanner,
	geoipReader *geoip2.Reader,
	cfg DaemonConfig,
	events DaemonEvents,
) *DaemonScheduler {
	if cfg.HighPriorityRatio <= 0 || cfg.HighPriorityRatio > 1.0 {
		cfg.HighPriorityRatio = 0.70
	}
	if cfg.CycleInterval <= 0 {
		cfg.CycleInterval = 10 * time.Second
	}

	return &DaemonScheduler{
		engine:        engine,
		store:         store,
		scannerEngine: scannerEngine,
		asnClient:     asnclient.NewClient(15 * time.Second),
		geoipReader:   geoipReader,
		config:        cfg,
		events:        events,
		randSource:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// log 辅助日志打印
func (d *DaemonScheduler) log(format string, args ...any) {
	if d.events.OnLog != nil {
		d.events.OnLog(fmt.Sprintf(format, args...))
	}
}

// PickNextASN 按照双队列优先级算法选取下一个待探测的 ASN
func (d *DaemonScheduler) PickNextASN() (*types.ASNRecord, error) {
	if d.store == nil {
		return nil, fmt.Errorf("TargetStore 未初始化")
	}

	// 如果指定了单个 ASN，直接查询并返回
	if d.config.SingleASN > 0 {
		rec, err := d.store.GetASN(d.config.SingleASN)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			rec = &types.ASNRecord{
				ASN:        d.config.SingleASN,
				Name:       fmt.Sprintf("AS%d", d.config.SingleASN),
				Priority:   100,
				ScanStatus: "pending",
			}
			_ = d.store.UpsertASNRecords([]*types.ASNRecord{rec})
		}
		return rec, nil
	}

	// 双队列分层调度：70% 概率优先选择队列 A（高优热门池 priority >= 80）
	if d.randSource.Float64() < d.config.HighPriorityRatio {
		rec, err := d.store.GetNextPendingASN(80)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return rec, nil
		}
	}

	// 30% 概率或高优池已无 pending 时，调度队列 B（全量长尾池）
	return d.store.GetNextPendingASN(0)
}

// Start 启动 24 小时全网扫描循环主流程
func (d *DaemonScheduler) Start(ctx context.Context) error {
	d.log("🚀 24小时全天候 ASN 全网扫描调度引擎启动中...")

	// 1. 系统重启或崩溃自愈：将异常残留的 scanning 状态全部回滚为 pending
	if err := d.store.ResetScanningASNs(); err != nil {
		d.log("⚠️ 重置残留 scanning 任务失败: %v", err)
	} else {
		d.log("🔄 已完成历史 scanning 任务状态自愈检查。")
	}

	// 2. 检查并确保 ASN 注册表基础底座存在数据
	mgr := asnclient.NewRegistryManager(d.store)
	if _, err := mgr.EnsureRegistrySeeded(); err != nil {
		d.log("⚠️ 检查 ASN 种子数据异常: %v", err)
	}

	// 3. 循环轮巡推进调度
	for {
		select {
		case <-ctx.Done():
			d.log("🛑 调度引擎收到停止信号，正在平稳退出...")
			return nil
		default:
		}

		// 挑选下一个待扫描 ASN
		asnRec, err := d.PickNextASN()
		if err != nil {
			d.log("❌ 获取待扫描 ASN 失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		// 若当前无待扫描的 ASN（说明全网所有已注册 ASN 均已扫描完毕）
		if asnRec == nil {
			if !d.config.Continuous {
				d.log("✅ 全网所有已注册 ASN 均已完成扫描。守护进程退出。")
				return nil
			}

			d.log("🎉 本轮全网 ASN 扫描已全部完成！休眠 %v 后自动开启新一轮全网资产保鲜轮巡...", d.config.CycleInterval)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(d.config.CycleInterval):
			}

			// 重置所有 completed 状态为 pending，开启下一轮大循环
			if err := d.store.ResetAllASNsStatus(); err != nil {
				d.log("❌ 重置 ASN 状态失败: %v", err)
			}
			continue
		}

		// 执行单个 ASN 的自动化全量扫描
		if err := d.processASN(ctx, asnRec); err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				d.log("🛑 任务在执行 AS%d 时被中断，断点已安全持久化。", asnRec.ASN)
				// 将当前未扫完的 ASN 重新退回 pending，便于下次秒级衔接
				_ = d.store.UpdateASNStatus(asnRec.ASN, "pending", 0)
				return nil
			}
			d.log("⚠️ 扫描 AS%d 出现异常: %v", asnRec.ASN, err)
		}
	}
}

// processASN 解析、过滤并扫描单个自治系统
func (d *DaemonScheduler) processASN(ctx context.Context, rec *types.ASNRecord) error {
	asnStr := fmt.Sprintf("AS%d", rec.ASN)
	d.log("📡 开始调度 %s [%s] (国家: %s, 权重: %d)...", asnStr, rec.Name, rec.Country, rec.Priority)

	// 标记为正在扫描
	_ = d.store.UpdateASNStatus(rec.ASN, "scanning", 0)
	startTime := time.Now()

	// 1. 通过 RIPE Stat 查询公布的前缀
	prefixes, err := d.asnClient.FetchPrefixes(ctx, asnStr)
	if err != nil {
		d.log("⚠️ 获取 %s 的公告 CIDR 失败: %v，跳过本自治系统", asnStr, err)
		_ = d.store.UpdateASNStatus(rec.ASN, "completed", 0)
		return nil
	}

	// 2. 国家过滤
	country := rec.Country
	if d.config.CountryFilter != "" {
		country = d.config.CountryFilter
	}
	if country != "" && d.geoipReader != nil {
		filtered, err := asnclient.FilterByCountry(prefixes, d.geoipReader, country)
		if err == nil && len(filtered) > 0 {
			prefixes = filtered
		}
	}

	// 3. IPv4 / IPv6 过滤
	prefixes = asnclient.FilterIPVersion(prefixes, d.config.IPv4Only, d.config.IPv6Only)
	if len(prefixes) == 0 {
		d.log("ℹ️ %s 没有符合 IP 版本/国家过滤的 CIDR 前缀，标记完成", asnStr)
		_ = d.store.UpdateASNStatus(rec.ASN, "completed", 0)
		return nil
	}

	totalIPs := CalculateTotalIPs(prefixes)
	d.log("🔍 %s 解析出 %d 个有效网段，覆盖约 %d 个 IP", asnStr, len(prefixes), totalIPs)

	if d.events.OnASNStart != nil {
		d.events.OnASNStart(rec, len(prefixes), totalIPs)
	}

	// 4. 组装 AutoScanner
	scanTimeoutSec := int(d.config.Timeout.Seconds())
	if scanTimeoutSec <= 0 {
		scanTimeoutSec = 3
	}
	filterCfg := types.RealityFilterConfig{
		ScanThreads: d.config.ScanThreads,
		ScanTimeout: scanTimeoutSec,
		RequireNoCN: true,
	}

	autoCfg := AutoScanConfig{
		CIDRs:      prefixes,
		MaxTargets: d.config.MaxTargetsPerASN,
		CheckAll:   true,
		Filter:     filterCfg,
		ASN:        asnStr,
		Country:    rec.Country,
	}

	autoEvents := AutoScanEvents{
		OnLog: func(msg string) {
			d.log("[%s] %s", asnStr, msg)
		},
		OnTargetFound: func(res *types.DetectionResult, count int, ip string, handshakeMs int64, statusCode int) {
			stars := CalculateTargetStars(res)
			targetRec := storage.DetectionResultToRecord(res, asnStr, rec.Country, ip, stars)
			if d.events.OnTargetFound != nil {
				d.events.OnTargetFound(targetRec)
			}
		},
	}

	scannerCore := NewAutoScanner(
		d.engine,
		d.store,
		d.scannerEngine,
		autoCfg,
		autoEvents,
	)

	// 执行扫描流水线
	res, scanErr := scannerCore.Run(ctx)
	duration := time.Since(startTime)

	if scanErr != nil {
		if errors.Is(scanErr, ErrAllCompleted) {
			d.log("✅ %s 的所有网段此前已完成扫描！", asnStr)
			_ = d.store.UpdateASNStatus(rec.ASN, "completed", 0)
			return nil
		}
		if errors.Is(scanErr, context.Canceled) || ctx.Err() != nil {
			return ctx.Err()
		}
		return scanErr
	}

	if res != nil && res.IsInterrupted {
		return context.Canceled
	}

	foundCount := 0
	if res != nil {
		foundCount = len(res.SuitableResults)
	}

	// 5. 扫描成功结束：更新 ASN 状态为 completed，并累加命中数
	_ = d.store.UpdateASNStatus(rec.ASN, "completed", foundCount)
	// 清理已全量完成的断点
	taskKey := fmt.Sprintf("%s_%s", asnStr, rec.Country)
	_ = d.store.ClearCheckpoints(taskKey)

	d.log("✨ %s 扫描完成！耗时: %v, 新发现优质 REALITY 目标: %d 个", asnStr, duration.Round(time.Second), foundCount)

	if d.events.OnASNComplete != nil {
		d.events.OnASNComplete(rec, foundCount, duration)
	}

	return nil
}

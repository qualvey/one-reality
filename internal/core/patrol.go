package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"RealityChecker/internal/network"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

// PatrolConfig 存量资产健康巡检配置
type PatrolConfig struct {
	Concurrency       int           `json:"concurrency"`
	Timeout           time.Duration `json:"timeout"`
	ProxyURL          string        `json:"proxy_url,omitempty"` // 巡检使用的代理地址
	HighStarAge       time.Duration `json:"high_star_age"`       // 4~5星高价值资产巡检周期 (默认 24h)
	NormalStarAge     time.Duration `json:"normal_star_age"`     // 2~3星普通资产巡检周期 (默认 72h)
	LogRetention      time.Duration `json:"log_retention"`       // 巡检日志保留时间 (默认 7 天)
	InactiveRetention time.Duration `json:"inactive_retention"`  // 失效下架资产归档/清理阈值 (默认 30 天)
	BatchSize         int           `json:"batch_size"`
}

// DefaultPatrolConfig 默认巡检配置
func DefaultPatrolConfig() PatrolConfig {
	return PatrolConfig{
		Concurrency:       30,
		Timeout:           3 * time.Second,
		HighStarAge:       24 * time.Hour,
		NormalStarAge:     72 * time.Hour,
		LogRetention:      7 * 24 * time.Hour,
		InactiveRetention: 30 * 24 * time.Hour,
		BatchSize:         100,
	}
}

// PatrolReport 巡检执行结果汇总
type PatrolReport struct {
	TotalChecked   int           `json:"total_checked"`
	Successful     int           `json:"successful"`
	Failed         int           `json:"failed"`
	CleanedLogs    int64         `json:"cleaned_logs"`
	CleanedTargets int64         `json:"cleaned_targets"`
	Duration       time.Duration `json:"duration"`
}

// PatrolEvents 巡检事件订阅
type PatrolEvents struct {
	OnLog           func(msg string)
	OnTargetChecked func(target *types.TargetRecord, success bool, ms int64, err error)
}

// PatrolWatchdog 存量 REALITY 资产健康巡检与生命周期守护服务
type PatrolWatchdog struct {
	store    *storage.TargetStore
	config   PatrolConfig
	events   PatrolEvents
	dialer   *net.Dialer
	dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewPatrolWatchdog 创建存量资产健康守护服务
func NewPatrolWatchdog(store *storage.TargetStore, cfg PatrolConfig, events PatrolEvents) *PatrolWatchdog {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 30
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.HighStarAge <= 0 {
		cfg.HighStarAge = 24 * time.Hour
	}
	if cfg.NormalStarAge <= 0 {
		cfg.NormalStarAge = 72 * time.Hour
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}

	dialer := &net.Dialer{
		Timeout: cfg.Timeout,
	}

	dialFunc := dialer.DialContext
	if cfg.ProxyURL != "" {
		if dc, err := network.MakeDialContext(cfg.ProxyURL, cfg.Timeout); err == nil && dc != nil {
			dialFunc = dc
		}
	}

	return &PatrolWatchdog{
		store:    store,
		config:   cfg,
		events:   events,
		dialer:   dialer,
		dialFunc: dialFunc,
	}
}

func (w *PatrolWatchdog) log(format string, args ...any) {
	if w.events.OnLog != nil {
		w.events.OnLog(fmt.Sprintf(format, args...))
	}
}

// CheckTarget 对指定资产发起轻量级快速 TLS 握手复测
func (w *PatrolWatchdog) CheckTarget(ctx context.Context, target *types.TargetRecord) (bool, int64, int, error) {
	if target == nil || target.Domain == "" {
		return false, 0, 0, fmt.Errorf("目标记录为空")
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

	// 1. 建立 TCP 连接
	tcpConn, err := w.dialFunc(ctx, "tcp", address)
	if err != nil {
		_ = w.store.UpdateTargetPatrolResult(target.Domain, target.IP, 0, 0, false, err.Error())
		return false, 0, 0, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}

	// 2. TLS 握手探针
	tlsCfg := &tls.Config{
		ServerName:         target.Domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	defer tlsConn.Close()

	start := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = w.store.UpdateTargetPatrolResult(target.Domain, target.IP, 0, 0, false, err.Error())
		return false, 0, 0, err
	}
	handshakeMS := time.Since(start).Milliseconds()

	// 3. 计算证书剩余有效期
	certDays := 0
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		certDays = int(time.Until(cert.NotAfter).Hours() / 24)
	}

	// 4. 更新数据库状态
	_ = w.store.UpdateTargetPatrolResult(target.Domain, target.IP, handshakeMS, certDays, true, "")
	return true, handshakeMS, certDays, nil
}

// RunOnce 执行单轮全库存量资产健康巡检与数据库整理
func (w *PatrolWatchdog) RunOnce(ctx context.Context) (*PatrolReport, error) {
	if w.store == nil {
		return nil, fmt.Errorf("TargetStore 未初始化")
	}

	startTime := time.Now()
	report := &PatrolReport{}

	// 1. 获取高星（4~5星）超期资产
	highStarTargets, err := w.store.GetTargetsForPatrol(4, w.config.HighStarAge, w.config.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("获取高星待巡检资产失败: %w", err)
	}

	// 2. 获取普通星级（2~3星）超期资产
	normalTargets, err := w.store.GetTargetsForPatrol(2, w.config.NormalStarAge, w.config.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("获取普通待巡检资产失败: %w", err)
	}

	// 合并并去重
	targetMap := make(map[string]*types.TargetRecord)
	for _, t := range highStarTargets {
		targetMap[t.Domain] = t
	}
	for _, t := range normalTargets {
		targetMap[t.Domain] = t
	}

	targets := make([]*types.TargetRecord, 0, len(targetMap))
	for _, t := range targetMap {
		targets = append(targets, t)
	}

	w.log("🛡️ 开始存量资产健康巡检：待检测目标 %d 个（高星 %d 个，普通 %d 个）...",
		len(targets), len(highStarTargets), len(normalTargets))

	if len(targets) > 0 {
		// 并发工作池执行巡检
		taskChan := make(chan *types.TargetRecord, len(targets))
		for _, t := range targets {
			taskChan <- t
		}
		close(taskChan)

		var wg sync.WaitGroup
		var mu sync.Mutex
		concurrency := w.config.Concurrency
		if concurrency > len(targets) {
			concurrency = len(targets)
		}

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for target := range taskChan {
					select {
					case <-ctx.Done():
						return
					default:
					}

					success, ms, _, checkErr := w.CheckTarget(ctx, target)
					mu.Lock()
					report.TotalChecked++
					if success {
						report.Successful++
					} else {
						report.Failed++
					}
					mu.Unlock()

					if w.events.OnTargetChecked != nil {
						w.events.OnTargetChecked(target, success, ms, checkErr)
					}
				}
			}()
		}
		wg.Wait()
	}

	// 3. 维护任务：清理过期巡检日志
	cleanedLogs, err := w.store.CleanExpiredPatrolLogs(w.config.LogRetention)
	if err == nil {
		report.CleanedLogs = cleanedLogs
	}

	// 4. 维护任务：清理长期失效资产（连续失效超过 30 天）
	cleanedTargets, err := w.store.DeleteExpiredInactiveTargets(w.config.InactiveRetention)
	if err == nil {
		report.CleanedTargets = cleanedTargets
	}

	// 5. 维护任务：整理 WAL 检查点
	_ = w.store.RunWALCheckpoint()

	report.Duration = time.Since(startTime)
	w.log("✅ 巡检轮次结束：共复测 %d 个目标（存活: %d, 失效降级: %d），清理超期日志 %d 条，清理僵尸资产 %d 个，耗时: %v",
		report.TotalChecked, report.Successful, report.Failed, report.CleanedLogs, report.CleanedTargets, report.Duration.Round(time.Millisecond))

	return report, nil
}

// Start 启动后台定时常驻巡检 Watchdog 循环
func (w *PatrolWatchdog) Start(ctx context.Context, checkInterval time.Duration) error {
	if checkInterval <= 0 {
		checkInterval = 1 * time.Hour
	}

	w.log("🐕 资产保鲜巡检守护进程 (Watchdog) 已启动，巡检频次: 每 %v", checkInterval)

	// 启动时立即执行一次巡检
	if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
		w.log("⚠️ 首次巡检异常: %v", err)
	}

	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log("🛑 巡检守护进程 (Watchdog) 收到退出信号，已平稳关闭。")
			return nil
		case <-ticker.C:
			if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
				w.log("⚠️ 周期巡检异常: %v", err)
			}
		}
	}
}

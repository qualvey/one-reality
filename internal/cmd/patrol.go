package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"RealityChecker/internal/app"
	"RealityChecker/internal/core"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/types"
)

// executePatrol 启动存量 REALITY 资产健康巡检与生命周期淘汰
func (r *RootCmd) executePatrol(args []string) {
	flags := flag.NewFlagSet("patrol", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	storePath := flags.String("store", "data/reality_targets.db", "SQLite 目标数据库路径")
	concurrency := flags.Int("concurrency", 30, "巡检并发协程数")
	flags.IntVar(concurrency, "c", 30, "巡检并发协程数 (缩写)")
	timeoutSec := flags.Int("timeout", 3, "单目标 TLS 探活超时秒数")
	isDaemon := flags.Bool("daemon", false, "常驻后台 Watchdog 模式运行")
	intervalMin := flags.Int("interval", 60, "后台 Watchdog 模式下巡检周期分钟数")

	if err := flags.Parse(args); err != nil {
		return
	}

	logger.PrintTimestampedMessage("正在初始化 REALITY 资产保鲜巡检守护服务 (Watchdog)...")

	// 1. 初始化统一应用依赖容器
	container, err := app.NewContainer(app.ContainerOptions{
		Config:     r.config,
		ExplicitDB: *storePath,
	})
	if err != nil {
		logger.PrintError(fmt.Sprintf("初始化应用容器失败: %v", err))
		return
	}
	defer container.Close()

	store, err := container.GetStore()
	if err != nil {
		logger.PrintError(fmt.Sprintf("打开目标数据库失败: %v", err))
		return
	}

	cfg := core.DefaultPatrolConfig()
	cfg.Concurrency = *concurrency
	cfg.Timeout = time.Duration(*timeoutSec) * time.Second

	events := core.PatrolEvents{
		OnLog: func(msg string) {
			logger.PrintTimestampedMessage("%s", msg)
		},
		OnTargetChecked: func(target *types.TargetRecord, success bool, ms int64, err error) {
			if success {
				logger.PrintTimestampedMessage("✅ [%-22s] 存活有效 | 握手: %dms | 剩余证书: %d天",
					target.Domain, ms, target.CertDays)
			} else {
				logger.PrintTimestampedMessage("❌ [%-22s] 握手失败: %v (连续失败 %d 次)",
					target.Domain, err, target.CheckFailCount+1)
			}
		},
	}

	watchdog := core.NewPatrolWatchdog(store, cfg, events)

	ctx, cancel := context.WithCancel(r.ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			logger.PrintTimestampedMessage("🛑 捕获退出信号，巡检守护服务平滑停机...")
			cancel()
		case <-ctx.Done():
		}
	}()

	if *isDaemon {
		cycleInterval := time.Duration(*intervalMin) * time.Minute
		if err := watchdog.Start(ctx, cycleInterval); err != nil && err != context.Canceled {
			logger.PrintError(fmt.Sprintf("巡检 Watchdog 异常: %v", err))
			return
		}
	} else {
		// 单次巡检并输出汇总报告
		report, err := watchdog.RunOnce(ctx)
		if err != nil {
			logger.PrintError(fmt.Sprintf("巡检执行失败: %v", err))
			return
		}
		fmt.Println("\n=== 存量资产健康巡检汇总报告 ===")
		fmt.Printf("检测资产总数 (Checked):      %d\n", report.TotalChecked)
		fmt.Printf("存活有效目标 (Healthy):      %d\n", report.Successful)
		fmt.Printf("异常或失效目标 (Unhealthy):  %d\n", report.Failed)
		fmt.Printf("超期日志清理 (Cleaned Logs): %d 条\n", report.CleanedLogs)
		fmt.Printf("失效资产清理 (Purged):       %d 个\n", report.CleanedTargets)
		fmt.Printf("总巡检耗时 (Duration):       %v\n", report.Duration.Round(time.Millisecond))
	}
}

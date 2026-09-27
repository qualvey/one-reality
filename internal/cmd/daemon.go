package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"RealityChecker/internal/adaptive"
	"RealityChecker/internal/core"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"

	"github.com/oschwald/geoip2-golang"
)

// executeDaemon 启动 24 小时全网 ASN 自动化扫描守护进程
func (r *RootCmd) executeDaemon(args []string) {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	storePath := flags.String("store", "data/reality_targets.db", "SQLite 目标与 ASN 数据库路径")
	dbPath := flags.String("db", "data/Country.mmdb", "GeoIP 国家数据库路径")
	threads := flags.Int("threads", 500, "扫描并发协程数")
	flags.IntVar(threads, "t", 500, "扫描并发协程数 (缩写)")
	timeoutSec := flags.Int("timeout", 3, "单 IP 探测超时秒数")
	singleASN := flags.Int("asn", 0, "仅持续扫描指定的单个 ASN (如 13335)")
	countryFilter := flags.String("country", "", "限定国家代码 (例如 US, JP, HK, DE)")
	ipv4Only := flags.Bool("ipv4-only", true, "仅扫描 IPv4 网段")
	flags.BoolVar(ipv4Only, "4", true, "仅扫描 IPv4 网段 (缩写)")
	ipv6Only := flags.Bool("ipv6-only", false, "仅扫描 IPv6 网段")
	flags.BoolVar(ipv6Only, "6", false, "仅扫描 IPv6 网段 (缩写)")
	highRatio := flags.Float64("high-ratio", 0.70, "热门高优池调度倾斜比率 (0.0~1.0)")
	cycleIntervalSec := flags.Int("interval", 10, "每轮扫描完成后的等待间隔秒数")
	verbose := flags.Bool("verbose", false, "详细模式，输出每个网段每个 IP 的实时扫描明细到 stdout")
	flags.BoolVar(verbose, "v", false, "详细模式 (缩写)")

	if err := flags.Parse(args); err != nil {
		return
	}

	ui.PrintTimestampedMessage("正在初始化 24小时 ASN 全网扫描守护进程...")

	// 1. 初始化目标数据库 (支持 SQLite 与 PostgreSQL)
	store, err := initStore(*storePath, r.config)
	if err != nil {
		ui.PrintError(fmt.Sprintf("打开目标数据库失败: %v", err))
		return
	}
	defer store.Close()

	// 2. 加载 GeoIP
	var geoipReader *geoip2.Reader
	if _, err := os.Stat(*dbPath); err == nil {
		geoipReader, err = geoip2.Open(*dbPath)
		if err != nil {
			ui.PrintTimestampedMessage("⚠️ 加载 GeoIP 数据库警告: %v (将跳过国家本地离线验证)", err)
		} else {
			defer geoipReader.Close()
		}
	}

	// 3. 构建扫描网络核心
	scanProxy := ""
	if r.config != nil && r.config.Proxy.Scanner && r.config.Proxy.URL != "" {
		scanProxy = r.config.Proxy.URL
	}
	scannerEngine := scanner.NewScanner(scanProxy)

	// 4. 构建配置与事件回调
	cfg := core.DaemonConfig{
		StorePath:         *storePath,
		CountryDBPath:     *dbPath,
		ScanThreads:       *threads,
		Timeout:           time.Duration(*timeoutSec) * time.Second,
		IPv4Only:          *ipv4Only,
		IPv6Only:          *ipv6Only,
		HighPriorityRatio: *highRatio,
		CycleInterval:     time.Duration(*cycleIntervalSec) * time.Second,
		SingleASN:         *singleASN,
		CountryFilter:     *countryFilter,
		Continuous:        true,
		Verbose:           *verbose,
	}

	events := core.DaemonEvents{
		OnLog: func(msg string) {
			ui.PrintTimestampedMessage("%s", msg)
		},
		OnASNStart: func(asn *types.ASNRecord, cidrCount int, totalIPs int64) {
			ui.PrintTimestampedMessage("🎯 [调度中枢] 选中自治系统 AS%d (%s, %s) - 启动 %d 个网段，约 %d 个 IP",
				asn.ASN, asn.Name, asn.Country, cidrCount, totalIPs)
		},
		OnASNComplete: func(asn *types.ASNRecord, foundTargets int, duration time.Duration) {
			ui.PrintTimestampedMessage("🏆 [调度中枢] 自治系统 AS%d 扫描完毕！新增有效资产 %d 个 (耗时 %v)",
				asn.ASN, foundTargets, duration.Round(time.Second))
		},
		OnScanRecord: func(probe *scanner.ProbeResult) {
			if !*verbose || probe == nil {
				return
			}
			if !probe.Success {
				ui.PrintTimestampedMessage("[-] %-15s:%-4d | 探活失败: %s", probe.IP, probe.Port, probe.FailureReason)
			} else {
				ui.PrintTimestampedMessage("[+] %-15s:%-4d | 握手成功: 提取域名 %s (ALPN: %s, 套件: %s)",
					probe.IP, probe.Port, probe.Result.CertDomain, probe.Result.ALPN, probe.Result.Curve)
			}
		},
		OnCandidateRejected: func(ip string, domain string, reason string) {
			if !*verbose {
				return
			}
			ui.PrintTimestampedMessage("[~] %-15s      | 域名未入选: %-25s | 原因: %s", ip, domain, reason)
		},
		OnAdaptiveAdjust: func(stats adaptive.LimiterStats) {
			ui.PrintTimestampedMessage("⚡ [自适应调谐] %s", stats.LastActionReason)
		},
		OnTargetFound: func(target *types.TargetRecord) {
			ui.PrintTimestampedMessage("⭐ 发现优质 REALITY 目标: %-25s (IP: %-15s, 握手: %dms, 评级: %d星)",
				target.Domain, target.IP, target.HandshakeMS, target.Stars)
		},
	}

	daemon := core.NewDaemonScheduler(
		r.engine,
		store,
		scannerEngine,
		geoipReader,
		cfg,
		events,
	)

	// 5. 监听平滑退出信号
	ctx, cancel := context.WithCancel(r.ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case sig := <-sigChan:
			ui.PrintTimestampedMessage("🛑 捕获系统退出信号 (%s)，通知扫描调度引擎平滑停机...", sig)
			cancel()
		case <-ctx.Done():
		}
	}()

	// 6. 运行守护循环
	if err := daemon.Start(ctx); err != nil && err != context.Canceled {
		ui.PrintError(fmt.Sprintf("守护进程异常终止: %v", err))
		return
	}

	ui.PrintTimestampedMessage("👋 24小时守护进程已优雅退出，所有扫描进度与断点均已妥善保存。")
}

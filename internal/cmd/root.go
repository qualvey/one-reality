package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"RealityChecker/internal/batch"
	"RealityChecker/internal/config"
	"RealityChecker/internal/core"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/ui"
	"RealityChecker/internal/version"
)

// RootCmd 根命令结构
type RootCmd struct {
	engine       *core.Engine
	batchManager *batch.Manager
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewRootCmd 创建根命令
func NewRootCmd() (*RootCmd, error) {
	// 加载配置
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %v", err)
	}

	// 初始化日志系统
	logger.Init(cfg.Log.Level, cfg.Log.File)

	// 创建引擎
	engine := core.NewEngine(cfg)
	if err := engine.Start(); err != nil {
		return nil, fmt.Errorf("启动引擎失败: %v", err)
	}

	// 创建批量管理器（共享引擎）
	batchManager := batch.NewManagerWithEngine(engine, cfg)
	if err := batchManager.Start(); err != nil {
		engine.Stop()
		return nil, fmt.Errorf("启动批量管理器失败: %v", err)
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sigChan := make(chan os.Signal, 2)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Printf("\n\n[!] 接收到中断信号 (Ctrl+C)，正在安全退出...\n")
		cancel()

		// 再次收到中断信号或超过 2 秒未退出时立即强制终止
		select {
		case <-sigChan:
			fmt.Printf("\n[!] 强制终止进程。\n")
			os.Exit(130)
		case <-time.After(2 * time.Second):
			os.Exit(130)
		}
	}()

	return &RootCmd{
		engine:       engine,
		batchManager: batchManager,
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Execute 执行命令
func (r *RootCmd) Execute() {
	defer r.cleanup()

	if len(os.Args) < 2 {
		ui.PrintUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		r.executeServe(os.Args[2:])
	case "get":
		r.executeGet(os.Args[2:])
	case "asn":
		executeASN(os.Args[2:])
	case "pipe":
		r.executePipe()
	case "auto":
		r.parseAndExecuteAuto(os.Args[2:])
	case "check":
		if len(os.Args) < 3 {
			ui.PrintErrorWithDetails(
				"错误：缺少域名参数",
				"用法: reality-checker check <domain>",
				"示例: reality-checker check apple.com",
			)
			os.Exit(1)
		}
		r.executeCheck(os.Args[2])
	case "batch":
		if len(os.Args) < 3 {
			ui.PrintErrorWithDetails(
				"错误：缺少域名参数",
				"用法: reality-checker batch <domain1> <domain2> <domain3> ...",
				"示例: reality-checker batch apple.com google.com microsoft.com",
			)
			os.Exit(1)
		}
		// 将所有参数（除了命令名）合并为空格分隔的字符串
		domainsStr := strings.Join(os.Args[2:], " ")
		r.executeBatch(domainsStr)
	case "csv":
		ui.PrintErrorWithDetails(
			"提示：'csv' 命令已废弃并整合",
			"请直接使用更为高效的流式管道命令：",
			"  cat file.csv | reality-checker pipe  (Linux/macOS)",
			"  Get-Content file.csv | reality-checker pipe  (Windows PowerShell)",
			"或者使用全自动内嵌扫描检测命令：",
			"  reality-checker auto <ip/cidr>",
		)
		os.Exit(1)
	case "version", "-v", "--version":
		r.showVersion()
	case "help", "-h", "--help":
		ui.PrintUsage()
	default:
		ui.PrintErrorWithDetails(
			fmt.Sprintf("错误：未知命令 '%s'", os.Args[1]),
			"可用命令: get, serve, auto, asn, pipe, check, batch, version",
		)
		os.Exit(1)
	}
}

// showVersion 显示版本信息
func (r *RootCmd) showVersion() {
	fmt.Printf("Reality协议目标网站检测工具\n")
	fmt.Printf("版本: %s\n", version.GetVersion())
	fmt.Printf("提交: %s\n", version.GetCommit())
	fmt.Printf("构建时间: %s\n", version.GetBuildTime())
	fmt.Printf("GitHub: https://github.com/V2RaySSR/RealityChecker\n")
}

// cleanup 清理资源
func (r *RootCmd) cleanup() {
	if r.batchManager != nil {
		r.batchManager.Stop()
	}
	if r.engine != nil {
		r.engine.Stop()
	}
	if r.cancel != nil {
		r.cancel()
	}
}

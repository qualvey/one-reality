package main

import (
	"fmt"
	"os"

	"RealityChecker/internal/cmd"
	"RealityChecker/internal/config"
	"RealityChecker/internal/data"
	"RealityChecker/internal/ui"
)

func main() {
	// 若无参数或显式请求 help (-h, --help, help)，立刻打印帮助信息并退出，避免触发耗时的数据校验
	if len(os.Args) < 2 {
		ui.PrintBanner()
		ui.PrintUsage()
		os.Exit(0)
	}

	subcmd := os.Args[1]
	if subcmd == "-h" || subcmd == "--help" || subcmd == "help" {
		ui.PrintBanner()
		ui.PrintUsage()
		os.Exit(0)
	}

	// 判断是否需要打印横幅（pipe/auto 或有 --quiet 标记时跳过横幅）
	shouldPrintBanner := true
	if subcmd == "pipe" || subcmd == "auto" || subcmd == "--quiet" || subcmd == "-q" {
		shouldPrintBanner = false
	}

	if shouldPrintBanner {
		ui.PrintBanner()
	}

	// 检查并下载必要的数据文件 (自动遵循 config.yaml 中的下载代理配置)
	downloadProxy := ""
	if cfg, err := config.LoadConfig(""); err == nil && cfg != nil {
		if cfg.Proxy.Download && cfg.Proxy.URL != "" {
			downloadProxy = cfg.Proxy.URL
		}
	}
	downloader := data.NewDownloader(downloadProxy)
	if err := downloader.EnsureDataFiles(); err != nil {
		fmt.Printf("⚠️ 数据文件目录初始化失败: %v，将继续运行\n", err)
	}

	// 创建根命令
	rootCmd, err := cmd.NewRootCmd()
	if err != nil {
		fmt.Printf("初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 执行命令
	rootCmd.Execute()
}




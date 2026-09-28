package main

import (
	"fmt"
	"os"
	"strings"

	"RealityChecker/internal/cmd"
	"RealityChecker/internal/config"
	"RealityChecker/internal/data"
)

// parseGlobalFlags 从命令行参数中提取全局选项 (-c/--config 配置文件路径)
func parseGlobalFlags(args []string) (string, []string) {
	var configPath string
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-c" || arg == "--config" {
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
				continue
			}
		} else if strings.HasPrefix(arg, "--config=") {
			configPath = strings.TrimPrefix(arg, "--config=")
			continue
		} else if strings.HasPrefix(arg, "-c=") {
			configPath = strings.TrimPrefix(arg, "-c=")
			continue
		}
		remaining = append(remaining, arg)
	}
	return configPath, remaining
}

func main() {
	configPath, remainingArgs := parseGlobalFlags(os.Args[1:])

	// 若无参数或显式请求 help (-h, --help, help)，立刻打印帮助信息并退出
	if len(remainingArgs) < 1 {
		cmd.PrintBanner()
		cmd.PrintUsage()
		os.Exit(0)
	}

	subcmd := remainingArgs[0]
	if subcmd == "-h" || subcmd == "--help" || subcmd == "help" {
		cmd.PrintBanner()
		cmd.PrintUsage()
		os.Exit(0)
	}

	// 判断是否需要打印横幅（pipe/auto 或有 --quiet 标记时跳过横幅）
	shouldPrintBanner := true
	if subcmd == "pipe" || subcmd == "auto" || subcmd == "--quiet" || subcmd == "-q" {
		shouldPrintBanner = false
	}

	if shouldPrintBanner {
		cmd.PrintBanner()
	}

	// 统一加载配置 (优先使用 -c/--config，其次探测环境变量/当前目录/二进制所在目录)
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Printf("⚠️ 加载配置失败: %v，将使用默认配置运行\n", err)
	}

	// 检查并下载必要的数据文件 (自动遵循配置中的下载代理配置)
	downloadProxy := ""
	if cfg != nil && cfg.Proxy.Download && cfg.Proxy.URL != "" {
		downloadProxy = cfg.Proxy.URL
	}
	downloader := data.NewDownloader(downloadProxy)
	if err := downloader.EnsureDataFiles(); err != nil {
		fmt.Printf("⚠️ 数据文件目录初始化失败: %v，将继续运行\n", err)
	}

	// 创建根命令
	rootCmd, err := cmd.NewRootCmd(cfg)
	if err != nil {
		fmt.Printf("初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 执行命令
	rootCmd.Execute(remainingArgs)
}




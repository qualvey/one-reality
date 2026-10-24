package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/cmd"
	"RealityChecker/internal/config"
	"RealityChecker/internal/data"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/network"
	"RealityChecker/internal/version"
)

// parseGlobalFlags 从命令行参数中提取全局选项 (-c/--config 配置文件路径, -f/--force 强制拉起标志)
func parseGlobalFlags(args []string) (string, bool, []string) {
	var configPath string
	force := false
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
		} else if arg == "-f" || arg == "--force" {
			force = true
			continue
		} else if strings.HasPrefix(arg, "--force=") {
			val := strings.TrimPrefix(arg, "--force=")
			force = (val == "true" || val == "1")
			continue
		}
		remaining = append(remaining, arg)
	}
	return configPath, force, remaining
}

func main() {
	configPath, force, remainingArgs := parseGlobalFlags(os.Args[1:])

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

	// 纯版本信息查询命令不触发网络与出口 IP 检测
	isVersionCmd := subcmd == "version" || subcmd == "-v" || subcmd == "--version"
	if !isVersionCmd {
		// 校验出口 IP（须为中国大陆 CN 节点，非 CN 须通过 --force 强制拉起）
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 4*time.Second)
		egressInfo, err := network.CheckEgress(checkCtx, "data/Country.mmdb")
		checkCancel()

		if err != nil {
			if force {
				if shouldPrintBanner {
					fmt.Printf("⚠️ 探测公网出口 IP 失败 (%v)，已检测到 --force 参数，强制继续运行...\n", err)
				}
			} else {
				cmdName := version.GetAppName()
				logger.PrintErrorWithDetails(
					fmt.Sprintf("❌ 无法检测本机公网出口 IP: %v", err),
					"原因分析:",
					"  启动时需要校验当前机器的公网出口是否为中国大陆 (CN) 网络。",
					"  当前网络可能未连接外网或所有探测服务均超时不可达。",
					"解决方式:",
					"  若确认在离线或非标准网络环境下继续执行，请追加 --force 或 -f 参数强制启动：",
					fmt.Sprintf("    %s --force %s", cmdName, strings.Join(remainingArgs, " ")),
				)
				os.Exit(1)
			}
		} else if !egressInfo.IsCN {
			if force {
				if shouldPrintBanner {
					fmt.Printf("⚠️ 当前出口 IP [%s] 归属地为 [%s / %s]，非中国大陆 (CN) 网络。已指定 --force 参数，强制拉起继续执行...\n", egressInfo.IP, egressInfo.CountryCode, egressInfo.CountryName)
				}
			} else {
				cmdName := version.GetAppName()
				logger.PrintErrorWithDetails(
					fmt.Sprintf("❌ 出口网络限制：当前出口 IP [%s] 归属地为 [%s / %s]，非中国大陆 (CN) 网络", egressInfo.IP, egressInfo.CountryCode, egressInfo.CountryName),
					"限制说明:",
					"  Reality 伪装目标探测必须基于中国大陆 (CN) 的出境网络视角，以保证测速与证书防封真实性。",
					"解决方式:",
					"  若确认在非 CN 网络环境下强制运行，请追加 --force 或 -f 参数拉起程序：",
					fmt.Sprintf("    %s --force %s", cmdName, strings.Join(remainingArgs, " ")),
				)
				os.Exit(1)
			}
		} else {
			if shouldPrintBanner {
				fmt.Printf("🌐 出口网络检测通过: %s (%s / %s)\n", egressInfo.IP, egressInfo.CountryCode, egressInfo.CountryName)
			}
		}
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

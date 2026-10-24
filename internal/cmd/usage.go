package cmd

import (
	"fmt"
	"strings"

	"RealityChecker/internal/version"
)

// PrintBanner 打印程序横幅
func PrintBanner() {
	fmt.Println()

	// 获取版本信息
	versionInfo := getVersionInfo()

	// 使用颜色代码
	white := "\033[37m"
	reset := "\033[0m"

	// 计算版本信息长度，确保居中对齐
	versionText := fmt.Sprintf("Reality Target 扫描器 %s", versionInfo)

	// 横幅宽度（与表格保持一致）
	width := 95

	// 计算字符显示宽度（中文字符占2个位置）
	versionDisplayWidth := getDisplayWidth(versionText)

	// 计算居中位置
	versionPadding := (width - 2 - versionDisplayWidth) / 2
	if versionPadding < 0 {
		versionPadding = 0
	}

	// 计算右侧剩余空间
	versionRightSpace := width - 2 - versionPadding - versionDisplayWidth
	if versionRightSpace < 0 {
		versionRightSpace = 0
	}

	fmt.Printf("%s╔%s╗%s\n", white, strings.Repeat("═", width-2), reset)
	fmt.Printf("%s║%s%s%s║%s\n", white, strings.Repeat(" ", versionPadding), versionText, strings.Repeat(" ", versionRightSpace), reset)
	fmt.Printf("%s║%s║%s\n", white, strings.Repeat(" ", width-2), reset)
	fmt.Printf("%s╚%s╝%s\n", white, strings.Repeat("═", width-2), reset)
	fmt.Println("")
}

// PrintUsage 打印使用说明
func PrintUsage() {
	appName := version.GetAppName()
	fmt.Printf("Reality协议目标网站检测器 %s\n\n", version.GetVersion())
	fmt.Println("用法:")
	fmt.Printf("  %s get <ip> [-n 5] [-s 3]  以指定IP极速获取优质伪装目标 (缓存优先+流式现扫)\n", appName)
	fmt.Printf("  %s serve [--port 8881]     启动Headless REST/SSE服务 (供WebUI/面板调用)\n", appName)
	fmt.Printf("  %s daemon [--threads 500]  启动24小时全天候全网ASN自动化扫描守护进程 (一键部署见 install.sh)\n", appName)
	fmt.Printf("  %s patrol [--daemon]       对本地库历史资产执行健康巡检复测与生命周期维护\n", appName)
	fmt.Printf("  %s auto <ip/cidr> [-v]     自动查ASN并并发扫描入库 (-v 输出每一条详细扫描记录)\n", appName)
	fmt.Printf("  %s asn <ASN> <国家>        查询ASN前缀并按国家过滤 (支持 --stats/--seed)\n", appName)
	fmt.Printf("  %s pipe                    从标准输入(Stdin)管道流式读取检测\n", appName)
	fmt.Printf("  %s check <domain>          检测单个域名\n", appName)
	fmt.Printf("  %s batch <d1> <d2> ...     批量检测多个域名\n", appName)
	fmt.Println("")
	fmt.Println("全局选项:")
	fmt.Println("  -c, --config FILE          指定配置文件路径 (默认自动探测)")
	fmt.Println("  -f, --force                强制启动运行，跳过非 CN (中国大陆) 出口 IP 的检测限制")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Printf("  %s get 85.155.184.100 -n 5 -s 4\n", appName)
	fmt.Printf("  %s get 85.155.184.100 --json\n", appName)
	fmt.Printf("  %s serve --port 8881\n", appName)
	fmt.Printf("  %s daemon -t 150 --interval 10 --token mytoken\n", appName)
	fmt.Printf("  %s auto 85.155.184.100 --limit 5\n", appName)
	fmt.Printf("  cat domains.txt | %s pipe\n", appName)
}

// getVersionInfo 获取版本信息字符串
func getVersionInfo() string {
	return version.GetVersion()
}

// getDisplayWidth 计算字符串的显示宽度（中文字符占2个位置）
func getDisplayWidth(s string) int {
	width := 0
	for _, r := range s {
		if r < 128 {
			width++
		} else {
			width += 2
		}
	}
	return width
}

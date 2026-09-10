package ui

import (
	"fmt"
	"strings"
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

	// 确保padding不为负数
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

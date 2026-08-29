package detectors

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
)

// NginxDefaultCheckResult Nginx/默认页检测结果
type NginxDefaultCheckResult struct {
	IsDefaultPage bool   // 是否为默认页
	PageType      string // 默认页类型 (如 "nginx", "openresty", "apache" 等)
	Reason        string // 判定原因
	Title         string // 提取的 HTML 标题
	ServerHeader  string // Server 响应头
}

// DetectNginxDefaultPage 检查 HTTP 响应是否属于 Nginx 或常见 Web 服务器的默认返回页
func DetectNginxDefaultPage(statusCode int, headers map[string]string, body []byte) *NginxDefaultCheckResult {
	result := &NginxDefaultCheckResult{
		IsDefaultPage: false,
		PageType:      "",
		Reason:        "",
		Title:         "",
		ServerHeader:  "",
	}

	// 提取 Server 响应头
	for k, v := range headers {
		if strings.EqualFold(k, "server") {
			result.ServerHeader = strings.TrimSpace(v)
			break
		}
	}

	// 提取 HTML Title
	if len(body) > 0 {
		matches := titleRegex.FindSubmatch(body)
		if len(matches) > 1 {
			rawTitle := string(matches[1])
			result.Title = strings.TrimSpace(strings.ReplaceAll(rawTitle, "\n", " "))
		}
	}

	titleLower := strings.ToLower(result.Title)
	bodyLower := strings.ToLower(string(body))
	serverLower := strings.ToLower(result.ServerHeader)

	// 1. 明确的 Nginx 欢迎页特征 (200 OK)
	if strings.Contains(titleLower, "welcome to nginx") {
		result.IsDefaultPage = true
		result.PageType = "nginx"
		result.Reason = "Nginx 默认欢迎页 (Title: " + result.Title + ")"
		return result
	}

	if strings.Contains(titleLower, "welcome to openresty") {
		result.IsDefaultPage = true
		result.PageType = "openresty"
		result.Reason = "OpenResty 默认欢迎页 (Title: " + result.Title + ")"
		return result
	}

	if strings.Contains(bodyLower, "if you see this page, the nginx web server is successfully installed") ||
		strings.Contains(bodyLower, "thank you for using nginx.") ||
		strings.Contains(bodyLower, "thank you for using openresty.") {
		result.IsDefaultPage = true
		result.PageType = "nginx"
		result.Reason = "Nginx 官方默认安装欢迎页内容"
		return result
	}

	// 2. 发行版定制的 Nginx 默认测试页 (Debian / Ubuntu / CentOS / Fedora / RHEL)
	if strings.Contains(titleLower, "test page for the nginx http server") ||
		strings.Contains(titleLower, "welcome to nginx on debian") ||
		strings.Contains(titleLower, "welcome to centos") && strings.Contains(bodyLower, "nginx") ||
		strings.Contains(bodyLower, "nginx on debian") ||
		strings.Contains(bodyLower, "nginx on ubuntu") ||
		strings.Contains(bodyLower, "nginx on fedora") {
		result.IsDefaultPage = true
		result.PageType = "nginx"
		result.Reason = "Linux 发行版 Nginx 默认测试页"
		return result
	}

	// 3. Nginx 默认错误页模版特征 (如 <center>nginx</center> 或 <center>nginx/1.24.0</center>)
	if isNginxErrorTemplate(bodyLower) {
		result.IsDefaultPage = true
		result.PageType = "nginx"
		if result.Title != "" {
			result.Reason = "Nginx 默认状态页模版 (" + result.Title + ")"
		} else {
			result.Reason = "Nginx 默认空白/错误状态页模版"
		}
		return result
	}

	// 4. 当 Server 为 Nginx/OpenResty 且响应体极短且包含典型默认签名时
	if (strings.Contains(serverLower, "nginx") || strings.Contains(serverLower, "openresty") || strings.Contains(serverLower, "tengine")) &&
		len(bytes.TrimSpace(body)) > 0 && len(bytes.TrimSpace(body)) < 1024 {
		if strings.Contains(bodyLower, "<center>") && (strings.Contains(bodyLower, "nginx") || strings.Contains(bodyLower, "openresty")) {
			result.IsDefaultPage = true
			result.PageType = "nginx"
			result.Reason = "Nginx 默认简洁状态页"
			return result
		}
	}

	return result
}

// isNginxErrorTemplate 检测是否为 Nginx 标准居中签名的默认 HTML 错误模板
func isNginxErrorTemplate(bodyLower string) bool {
	// Nginx 标准错误页底部: <center>nginx</center> 或 <center>nginx/x.y.z</center>
	if strings.Contains(bodyLower, "<center>nginx</center>") ||
		strings.Contains(bodyLower, "<center>nginx/") ||
		strings.Contains(bodyLower, "<center>openresty</center>") ||
		strings.Contains(bodyLower, "<center>openresty/") ||
		strings.Contains(bodyLower, "<center>tengine</center>") ||
		strings.Contains(bodyLower, "<center>tengine/") {
		return true
	}
	return false
}

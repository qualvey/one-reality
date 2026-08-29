package detectors

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
)

// NginxDefaultCheckResult Nginx/默认页/占位回显页检测结果
type NginxDefaultCheckResult struct {
	IsDefaultPage bool   // 是否为默认页或占位页
	PageType      string // 页面类型 (如 "nginx", "openresty", "apache", "caddy", "dummy", "empty", "tunnel" 等)
	Reason        string // 判定原因
	Title         string // 提取的 HTML 标题
	ServerHeader  string // Server 响应头
}

// DetectNginxDefaultPage 检查 HTTP 响应是否属于 Web 服务器默认页、Tunnel 占位页或短回显服务
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

	trimmedBody := bytes.TrimSpace(body)

	// 0. 空响应体检测
	if len(trimmedBody) == 0 {
		result.IsDefaultPage = true
		result.PageType = "empty"
		result.Reason = "HTTP 响应体为空"
		return result
	}

	// 提取 HTML Title
	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		rawTitle := string(matches[1])
		result.Title = strings.TrimSpace(strings.ReplaceAll(rawTitle, "\n", " "))
	}

	titleLower := strings.ToLower(result.Title)
	bodyLower := strings.ToLower(string(trimmedBody))
	serverLower := strings.ToLower(result.ServerHeader)

	// 1. Tunnel / 代理占位 / Mock 服务特征匹配 (如 "hewwo from tuwunel woof!", "boringproxy", "default backend")
	if strings.Contains(bodyLower, "tuwunel") ||
		strings.Contains(bodyLower, "boringproxy") ||
		strings.Contains(bodyLower, "default backend - 404") ||
		strings.Contains(bodyLower, "default backend") ||
		(strings.Contains(bodyLower, "tunnel") && len(trimmedBody) < 200) ||
		(strings.Contains(bodyLower, "404 page not found") && len(trimmedBody) < 200) {
		result.IsDefaultPage = true
		result.PageType = "tunnel/dummy"
		sample := truncateString(string(trimmedBody), 40)
		result.Reason = "识别为 Tunnel 代理或 Dummy 占位服务: \"" + sample + "\""
		return result
	}

	// 2. 极短无任何 HTML 结构的纯文本回显/占位测试服务 (如 "ok", "hello world", "test", 20-100字节的纯文本字符串)
	if len(trimmedBody) < 150 {
		hasHTMLStructure := strings.Contains(bodyLower, "<html") ||
			strings.Contains(bodyLower, "<head") ||
			strings.Contains(bodyLower, "<body") ||
			strings.Contains(bodyLower, "<div") ||
			strings.Contains(bodyLower, "<p") ||
			strings.Contains(bodyLower, "<script") ||
			strings.Contains(bodyLower, "<!doctype") ||
			strings.Contains(bodyLower, "<?xml")

		if !hasHTMLStructure {
			result.IsDefaultPage = true
			result.PageType = "dummy"
			sample := truncateString(string(trimmedBody), 40)
			result.Reason = "无有效 HTML 结构的极短纯文本占位/回显: \"" + sample + "\""
			return result
		}
	}

	// 3. 明确的 Nginx / OpenResty 欢迎页与安装页特征
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

	// 4. Linux 发行版定制的 Nginx 默认测试页 (Debian / Ubuntu / CentOS / Fedora / RHEL)
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

	// 5. Apache / Caddy / Traefik / IIS 默认页特征
	if strings.Contains(titleLower, "apache2 default page") ||
		strings.Contains(titleLower, "apache2 debian default page") ||
		strings.Contains(titleLower, "apache2 ubuntu default page") ||
		strings.Contains(titleLower, "welcome to the apache http server") ||
		(strings.Contains(bodyLower, "it works!") && len(trimmedBody) < 500) {
		result.IsDefaultPage = true
		result.PageType = "apache"
		result.Reason = "Apache 默认测试页 / It works!"
		return result
	}

	if strings.Contains(titleLower, "caddy works!") ||
		strings.Contains(titleLower, "welcome to caddy") ||
		strings.Contains(bodyLower, "caddy web server") && strings.Contains(bodyLower, "welcome") {
		result.IsDefaultPage = true
		result.PageType = "caddy"
		result.Reason = "Caddy 默认欢迎页"
		return result
	}

	if strings.Contains(titleLower, "iis windows server") ||
		strings.Contains(bodyLower, "iis-8.5") ||
		strings.Contains(bodyLower, "iis-10.0") ||
		strings.Contains(bodyLower, "welcome to iis") {
		result.IsDefaultPage = true
		result.PageType = "iis"
		result.Reason = "Microsoft IIS 默认欢迎页"
		return result
	}

	// 6. Nginx 默认居中错误页模版特征 (如 <center>nginx</center> 或 <center>nginx/1.24.0</center>)
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

	// 7. 当 Server 为 Nginx/OpenResty 且响应体极短且包含典型默认签名时
	if (strings.Contains(serverLower, "nginx") || strings.Contains(serverLower, "openresty") || strings.Contains(serverLower, "tengine")) &&
		len(trimmedBody) < 1024 {
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

func truncateString(s string, maxLen int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

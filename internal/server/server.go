package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"RealityChecker/internal/logger"
	"RealityChecker/internal/service"
	"RealityChecker/internal/types"
	"RealityChecker/web"
)

// ServerConfig HTTP 服务配置
type ServerConfig struct {
	Addr           string        `json:"addr"`
	APIToken       string        `json:"api_token"`
	AllowedOrigins []string      `json:"allowed_origins"`
	ReadTimeout    time.Duration `json:"read_timeout"`
	WriteTimeout   time.Duration `json:"write_timeout"`
}

// DefaultServerConfig 返回默认配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:           ":8881",
		APIToken:       "",
		AllowedOrigins: []string{"*"},
		ReadTimeout:    30 * time.Second,
		// SSE 连接可能持续超过任意固定时长。空值表示不设置全局写超时，
		// 流式接口通过心跳保持代理连接活跃。
		WriteTimeout: 0,
	}
}

// TargetServer 提供 REST & SSE 目标的 HTTP 服务
type TargetServer struct {
	cfg        ServerConfig
	service    *service.ProvisionService
	httpServer *http.Server
}

// NewTargetServer 创建 TargetServer 实例
func NewTargetServer(cfg ServerConfig, svc *service.ProvisionService) *TargetServer {
	if cfg.Addr == "" {
		cfg.Addr = ":8881"
	}
	if cfg.WriteTimeout < 0 {
		cfg.WriteTimeout = 0
	}

	ts := &TargetServer{
		cfg:     cfg,
		service: svc,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", ts.handleHealth)
	mux.HandleFunc("/api/stats", ts.handleStats)
	mux.HandleFunc("/api/filter/default", ts.handleDefaultFilter)
	mux.HandleFunc("/api/targets/smart", ts.handleTargetsSmart)
	mux.HandleFunc("/api/targets/stream", ts.handleTargetsStream)
	mux.HandleFunc("/api/scan/tasks", ts.handleScanTasks)
	mux.HandleFunc("/api/scan/tasks/", ts.handleScanTask)
	mux.HandleFunc("/api/targets/check", ts.handleTargetsCheck)
	mux.HandleFunc("/api/targets", ts.handleTargetsManage)
	mux.HandleFunc("/api/targets/", ts.handleTargetItemAction)
	mux.HandleFunc("/api/asns", ts.handleASNs)

	// 静态文件支持 (优先本地磁盘 web/dist 便于开发，回退至内嵌 go:embed 静态资源实现单二进制独立分发)
	webDistPath := "web/dist"
	var staticFS http.FileSystem
	var indexData []byte

	if fi, err := os.Stat(webDistPath); err == nil && fi.IsDir() {
		staticFS = http.Dir(webDistPath)
		indexData, _ = os.ReadFile(filepath.Join(webDistPath, "index.html"))
	} else if web.HasDist() {
		staticFS = http.FS(web.DistFS())
		if f, err := web.DistFS().Open("index.html"); err == nil {
			indexData, _ = io.ReadAll(f)
			_ = f.Close()
		}
	}

	if staticFS != nil {
		fileServer := http.FileServer(staticFS)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}

			// SPA 单页路由支持: 检查文件是否存在
			cleanPath := strings.TrimPrefix(filepath.Clean(r.URL.Path), "/")
			if cleanPath == "" || cleanPath == "." {
				cleanPath = "index.html"
			}

			f, err := staticFS.Open(cleanPath)
			if err != nil {
				if len(indexData) > 0 {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(indexData)
					return
				}
				http.NotFound(w, r)
				return
			}
			_ = f.Close()

			fileServer.ServeHTTP(w, r)
		})
	}

	handler := ts.corsMiddleware(ts.loggingMiddleware(ts.authMiddleware(mux)))

	ts.httpServer = &http.Server{
		Addr:         cfg.Addr,
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return ts
}

// Start 启动 HTTP 服务（阻塞运行直到 context 取消或异常）
func (s *TargetServer) Start() error {
	logger.Info("🌐 HTTP 服务启动，监听于 http://%s", s.cfg.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown 优雅关闭 HTTP 服务
func (s *TargetServer) Shutdown(ctx context.Context) error {
	logger.Info("正在优雅停止 HTTP 服务...")
	if s.httpServer != nil {
		err := s.httpServer.Shutdown(ctx)
		if err == nil {
			logger.Info("HTTP 服务已安全关闭。")
		}
		return err
	}
	return nil
}

// statusLoggingResponseWriter 捕获 HTTP 响应状态码及字节大小并透传 Flush/Hijack
type statusLoggingResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *statusLoggingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusLoggingResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

func (w *statusLoggingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusLoggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Unwrap 让 http.ResponseController 能够访问底层连接，例如为 SSE 清除
// http.Server.WriteTimeout 设置的初始写截止时间。
func (w *statusLoggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// getClientIP 提取请求的真实客户端 IP
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 && strings.TrimSpace(ips[0]) != "" {
			return strings.TrimSpace(ips[0])
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// loggingMiddleware 全局请求审计与性能耗时日志中间件
func (s *TargetServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusLoggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		clientIP := getClientIP(r)

		// 静态前端资源请求 (如 .js, .css, .ico 等) 仅在 debug 级别记录，防止前端刷新导致日志刷屏
		isStatic := !strings.HasPrefix(r.URL.Path, "/api/") &&
			(strings.HasSuffix(r.URL.Path, ".js") ||
				strings.HasSuffix(r.URL.Path, ".css") ||
				strings.HasSuffix(r.URL.Path, ".ico") ||
				strings.HasSuffix(r.URL.Path, ".svg") ||
				strings.HasSuffix(r.URL.Path, ".woff2") ||
				strings.HasSuffix(r.URL.Path, ".png") ||
				strings.HasSuffix(r.URL.Path, ".jpg"))

		if isStatic {
			logger.Debug("[HTTP] %s %s - %d (%v) | %s", r.Method, r.RequestURI, rw.statusCode, duration, clientIP)
			return
		}

		// API 接口与业务路由的标准审计日志输出
		if rw.statusCode >= 500 {
			logger.Error("[HTTP] %s %s - %d %s (%v) | 客户端: %s", r.Method, r.RequestURI, rw.statusCode, http.StatusText(rw.statusCode), duration, clientIP)
		} else if rw.statusCode >= 400 {
			logger.Warn("[HTTP] %s %s - %d %s (%v) | 客户端: %s", r.Method, r.RequestURI, rw.statusCode, http.StatusText(rw.statusCode), duration, clientIP)
		} else {
			logger.Info("[HTTP] %s %s - %d %s (%v) | 客户端: %s", r.Method, r.RequestURI, rw.statusCode, http.StatusText(rw.statusCode), duration, clientIP)
		}
	})
}

// corsMiddleware 跨域处理中间件
func (s *TargetServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowOrigin := "*"
		if len(s.cfg.AllowedOrigins) > 0 && s.cfg.AllowedOrigins[0] != "*" {
			for _, o := range s.cfg.AllowedOrigins {
				if o == origin {
					allowOrigin = origin
					break
				}
			}
		}

		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware 鉴权中间件 (支持 Authorization: Bearer <token> 与 Query ?token=<token>)
func (s *TargetServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIToken == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 排除健康检查等公开接口与静态页面路由
		if r.URL.Path == "/api/health" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		// OPTIONS 请求直接放行（CORS 预检）
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		token := ""
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				token = strings.TrimSpace(parts[1])
			} else {
				token = strings.TrimSpace(authHeader)
			}
		}

		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}

		if token != s.cfg.APIToken {
			logger.Warn("⚠️ 接口鉴权拦截: 未提供有效 API Token (客户端: %s, URI: %s)", getClientIP(r), r.RequestURI)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":  401,
				"error": "Unauthorized: invalid or missing API token",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth 健康检查
func (s *TargetServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    200,
		"status":  "ok",
		"version": "1.2.0",
		"time":    time.Now().Format(time.RFC3339),
	})
}

// handleStats 资产概览统计数据
func (s *TargetServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats, err := s.service.GetStats()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": 200,
		"data": stats,
	})
}

// handleTargetsSmart 核心接口：基于目标 IP 动态加权打分推荐 (同 ASN 绝对置顶)
func (s *TargetServer) handleTargetsSmart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	req := parseProvisionRequest(r)

	if req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":  400,
			"error": "Missing 'ip' query parameter",
		})
		return
	}

	ranked, summary, err := s.service.GetSmartTargets(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
		return
	}

	logger.Info("🎯 [API] 智能匹配: 客户端 %s 查询 IP: %s (匹配 %d 个推荐节点, 所属ASN: %s)",
		getClientIP(r), req.IP, len(ranked), summary.ASN)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": 200,
		"data": map[string]any{
			"summary": summary,
			"targets": ranked,
		},
	})
}

// handleTargetsCheck 在线即时检测单个域名/IP 并持久化入库
func (s *TargetServer) handleTargetsCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "error": "Invalid request payload: " + err.Error()})
		return
	}

	if strings.TrimSpace(payload.Domain) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "error": "Domain is required"})
		return
	}

	rec, err := s.service.CheckSingleDomain(r.Context(), payload.Domain, payload.IP)
	if err != nil {
		logger.Warn("❌ [API] 在线复核失败: 域名=%s, IP=%s, 错误: %v (客户端: %s)", payload.Domain, payload.IP, err, getClientIP(r))
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "error": err.Error()})
		return
	}

	logger.Info("🔍 [API] 在线复核完成: 域名=%s, IP=%s, 评级=%d星, 握手=%dms (客户端: %s)",
		rec.Domain, rec.IP, rec.Stars, rec.HandshakeMS, getClientIP(r))

	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    200,
		"message": "Domain detected and saved successfully",
		"data":    rec,
	})
}

// handleDefaultFilter 返回系统全局默认过滤与选型偏好配置
func (s *TargetServer) handleDefaultFilter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	filter := s.service.GetDefaultFilter()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": 200,
		"data": filter,
	})
}

// handleTargetsManage 资产库管理接口 (GET 分页检索)
func (s *TargetServer) handleTargetsManage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		q := r.URL.Query()

		var isActive *bool
		if val := q.Get("is_active"); val != "" {
			b := parseBool(val)
			isActive = &b
		}

		var requireNoCDN *bool
		if val := q.Get("require_no_cdn"); val != "" {
			b := parseBool(val)
			requireNoCDN = &b
		}

		var requireNoHot *bool
		if val := q.Get("require_no_hot"); val != "" {
			b := parseBool(val)
			requireNoHot = &b
		}

		var requireNoDefaultPage *bool
		if val := q.Get("require_no_default_page"); val != "" {
			b := parseBool(val)
			requireNoDefaultPage = &b
		}

		var requireNoCN *bool
		if val := q.Get("require_no_cn"); val != "" {
			b := parseBool(val)
			requireNoCN = &b
		}

		var maxHandshakeMS int64
		if val := q.Get("max_handshake_ms"); val != "" {
			if ms, err := strconv.ParseInt(val, 10, 64); err == nil && ms > 0 {
				maxHandshakeMS = ms
			}
		}

		var minCertDays int
		if val := q.Get("min_cert_days"); val != "" {
			if days, err := strconv.Atoi(val); err == nil && days > 0 {
				minCertDays = days
			}
		}

		var excludeStatus []int
		if val := q.Get("exclude_status"); val != "" {
			for _, part := range strings.Split(val, ",") {
				if code, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
					excludeStatus = append(excludeStatus, code)
				}
			}
		}
		successOnly := parseBool(q.Get("success_only"))

		page, _ := strconv.Atoi(q.Get("page"))
		if page <= 0 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(q.Get("page_size"))
		if pageSize <= 0 {
			pageSize = 20
		}
		minStars, _ := strconv.Atoi(q.Get("min_stars"))

		opts := types.TargetQueryOptions{
			Keyword:              q.Get("keyword"),
			ASN:                  q.Get("asn"),
			Country:              q.Get("country"),
			MinStars:             minStars,
			IsActive:             isActive,
			RequireNoCDN:         requireNoCDN,
			RequireNoHot:         requireNoHot,
			RequireNoDefaultPage: requireNoDefaultPage,
			RequireNoCN:          requireNoCN,
			DomainSuffixes:       q.Get("domain_suffixes"),
			MaxHandshakeMS:       maxHandshakeMS,
			MinCertDays:          minCertDays,
			ExcludeStatus:        excludeStatus,
			SuccessOnly:          successOnly,
			SortBy:               q.Get("sort_by"),
			Page:                 page,
			PageSize:             pageSize,
		}

		items, total, err := s.service.QueryTargets(opts)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 200,
			"data": map[string]any{
				"items":     items,
				"total":     total,
				"page":      page,
				"page_size": pageSize,
			},
		})
		return
	}

	http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
}

// handleTargetItemAction 对单个资产执行状态修改或删除
func (s *TargetServer) handleTargetItemAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	domain := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	domain = strings.TrimSpace(domain)
	starAction := strings.HasSuffix(domain, "/star")
	dislikeAction := strings.HasSuffix(domain, "/dislike")
	if starAction {
		domain = strings.TrimSpace(strings.TrimSuffix(domain, "/star"))
	}
	if dislikeAction {
		domain = strings.TrimSpace(strings.TrimSuffix(domain, "/dislike"))
	}

	if domain == "" {
		http.Error(w, `{"code": 400, "error": "Missing domain parameter"}`, http.StatusBadRequest)
		return
	}

	if starAction {
		var starred bool
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			starred = true
		case http.MethodDelete:
			starred = false
		default:
			http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if err := s.service.UpdateTargetStarred(domain, starred); err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 404, "error": err.Error()})
			return
		}
		logger.Info("⭐ [API] %s 资产: domain=%s (客户端: %s)", map[bool]string{true: "收藏", false: "取消收藏"}[starred], domain, getClientIP(r))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":       200,
			"is_starred": starred,
			"message":    "Updated successfully",
		})
		return
	}

	if dislikeAction {
		var disliked bool
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			disliked = true
		case http.MethodDelete:
			disliked = false
		default:
			http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if err := s.service.UpdateTargetDisliked(domain, disliked); err != nil {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 404, "error": err.Error()})
			return
		}
		logger.Info("👎 [API] %s 资产: domain=%s (客户端: %s)", map[bool]string{true: "标记差评", false: "取消差评"}[disliked], domain, getClientIP(r))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":        200,
			"is_disliked": disliked,
			"message":     "Updated successfully",
		})
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var payload struct {
			IsActive   *bool `json:"is_active"`
			IsStarred  *bool `json:"is_starred"`
			IsDisliked *bool `json:"is_disliked"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "error": err.Error()})
			return
		}

		if payload.IsActive != nil {
			if err := s.service.UpdateTargetActive(domain, *payload.IsActive); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
				return
			}
		}
		if payload.IsStarred != nil {
			if err := s.service.UpdateTargetStarred(domain, *payload.IsStarred); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
				return
			}
		}
		if payload.IsDisliked != nil {
			if err := s.service.UpdateTargetDisliked(domain, *payload.IsDisliked); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
				return
			}
		}
		logger.Info("✏️ [API] 变更节点状态: domain=%s, is_active=%v, is_starred=%v, is_disliked=%v (客户端: %s)", domain, payload.IsActive, payload.IsStarred, payload.IsDisliked, getClientIP(r))
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "message": "Updated successfully"})

	case http.MethodDelete:
		if err := s.service.DeleteTarget(domain); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
			return
		}
		logger.Info("🗑️ [API] 删除资产记录: domain=%s (客户端: %s)", domain, getClientIP(r))
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "message": "Deleted successfully"})

	default:
		http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleASNs 查询 ASN 登记表
func (s *TargetServer) handleASNs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	q := r.URL.Query()

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	minPriority, _ := strconv.Atoi(q.Get("min_priority"))
	status := q.Get("status")

	list, err := s.service.ListASNs(status, minPriority, limit, offset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": 200,
		"data": list,
	})
}

// parseProvisionRequest 解析 Query 参数为 ProvisionRequest
func parseProvisionRequest(r *http.Request) service.ProvisionRequest {
	q := r.URL.Query()

	limit := 10
	if val := q.Get("limit"); val != "" {
		if l, err := strconv.Atoi(val); err == nil && l > 0 {
			limit = l
		}
	}

	minStars := 3
	if val := q.Get("min_stars"); val != "" {
		if s, err := strconv.Atoi(val); err == nil && s > 0 {
			minStars = s
		}
	}

	fresh := parseBool(q.Get("fresh"))
	ipv4Only := parseBool(q.Get("ipv4_only")) || parseBool(q.Get("4"))
	ipv6Only := parseBool(q.Get("ipv6_only")) || parseBool(q.Get("6"))
	requireNoCN := parseBool(q.Get("require_no_cn")) || parseBool(q.Get("no_cn"))
	scanAll := parseBool(q.Get("scan_all")) || parseBool(q.Get("all"))

	return service.ProvisionRequest{
		IP:          q.Get("ip"),
		Limit:       limit,
		MinStars:    minStars,
		Fresh:       fresh,
		Country:     q.Get("country"),
		IPv4Only:    ipv4Only,
		IPv6Only:    ipv6Only,
		RequireNoCN: requireNoCN,
		ScanAll:     scanAll,
	}
}

func parseBool(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// handleScanTasks 创建由前端拥有的后台扫描任务。
func (s *TargetServer) handleScanTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req service.ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"code": 400, "error": "Invalid request payload"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.IP) == "" {
		http.Error(w, `{"code": 400, "error": "Missing ip"}`, http.StatusBadRequest)
		return
	}

	info, err := s.service.StartFrontendScan(req)
	if err != nil {
		http.Error(w, `{"code": 500, "error": "Unable to create scan task"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": info})
}

// handleScanTask 返回或停止由前端创建的后台扫描任务。
func (s *TargetServer) handleScanTask(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimPrefix(r.URL.Path, "/api/scan/tasks/")
	taskID = strings.TrimSpace(taskID)
	if taskID == "" || strings.Contains(taskID, "/") {
		http.Error(w, `{"code": 400, "error": "Invalid scan task id"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		info, err := s.service.GetFrontendScanTask(taskID)
		if err != nil {
			http.Error(w, `{"code": 404, "error": "Scan task not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "data": info})
	case http.MethodDelete:
		if err := s.service.StopFrontendScan(taskID); err != nil {
			http.Error(w, `{"code": 404, "error": "Scan task not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    200,
			"message": "Scan task stop requested",
			"task_id": taskID,
		})
	default:
		http.Error(w, `{"code": 405, "error": "Method Not Allowed"}`, http.StatusMethodNotAllowed)
	}
}

// handleTargetsStream 处理可断线重连的后台 SSE 流式返回。
// 新请求会创建独立于 HTTP 请求生命周期的 frontend task；带 task_id
// 的请求只订阅该任务，因此浏览器关闭不会取消服务端扫描。
func (s *TargetServer) handleTargetsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		logger.Error("❌ [API] SSE 流式探测不可用：响应写入器不支持 Flush (客户端: %s)", getClientIP(r))
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	// 即使调用方显式配置了全局 WriteTimeout，SSE 也不能沿用这个绝对
	// 截止时间，否则长扫描会在固定时长后被 net/http 强制断开。
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	req := parseProvisionRequest(r)
	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if taskID == "" && req.IP == "" {
		logger.Error("❌ [API] SSE 流式探测请求缺少 IP (客户端: %s)", getClientIP(r))
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	if taskID == "" {
		info, err := s.service.StartFrontendScan(req)
		if err != nil {
			http.Error(w, `{"code": 500, "error": "Unable to create scan task"}`, http.StatusInternalServerError)
			return
		}
		taskID = info.TaskID
		logger.Info("📡 [API] 创建前端后台扫描任务: task=%s, 客户端=%s, 查询 IP=%s", taskID, getClientIP(r), req.IP)
	} else {
		logger.Info("📡 [API] 前端扫描任务重连: task=%s, 客户端=%s", taskID, getClientIP(r))
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	emit := func(evt service.ProvisionEvent) error {
		dataBytes, err := json.Marshal(evt.Data)
		if err != nil {
			logger.Error("❌ [API] SSE 序列化事件失败: event=%s, IP=%s, error=%v", evt.Event, req.IP, err)
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, string(dataBytes))
		if err != nil {
			logger.Error("❌ [API] SSE 写入事件失败: event=%s, IP=%s, 客户端=%s, error=%v", evt.Event, req.IP, getClientIP(r), err)
			return err
		}
		flusher.Flush()
		return nil
	}

	ch, unsubscribe, err := s.service.SubscribeFrontendScan(taskID)
	if err != nil {
		http.Error(w, `{"code": 404, "error": "Scan task not found"}`, http.StatusNotFound)
		return
	}
	defer unsubscribe()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			// Only detach this SSE subscriber. The task itself owns its context
			// and intentionally continues running in the background.
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			if err := emit(evt); err != nil {
				logger.Warn("⚠️ [API] SSE 订阅连接中断: task=%s, 客户端=%s, error=%v", taskID, getClientIP(r), err)
				return
			}
		case <-heartbeat.C:
			// SSE 注释帧不会触发前端事件，但能防止反向代理把空闲
			// 长连接误判为断开。
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				logger.Warn("⚠️ [API] SSE 心跳写入失败: task=%s, 客户端=%s, error=%v", taskID, getClientIP(r), err)
				return
			}
			flusher.Flush()
		}
	}
}

// handleTargetsJSON 处理标准单次 JSON 批量返回
func (s *TargetServer) handleTargetsJSON(w http.ResponseWriter, r *http.Request) {
	req := parseProvisionRequest(r)
	if req.IP == "" {
		http.Error(w, `{"code": 400, "error": "Missing 'ip' query parameter"}`, http.StatusBadRequest)
		return
	}

	var initData *service.InitEventData
	var targets []service.TargetItem
	var doneData *service.DoneEventData

	err := s.service.StreamTargets(r.Context(), req, func(evt service.ProvisionEvent) error {
		switch evt.Event {
		case "init":
			if d, ok := evt.Data.(service.InitEventData); ok {
				initData = &d
			}
		case "target":
			if item, ok := evt.Data.(service.TargetItem); ok {
				targets = append(targets, item)
			}
		case "done":
			if d, ok := evt.Data.(service.DoneEventData); ok {
				doneData = &d
			}
		}
		return nil
	})

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		logger.Error("❌ [API] 目标扫描 JSON 请求失败: IP=%s, 客户端=%s, error=%v", req.IP, getClientIP(r), err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":  500,
			"error": err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    200,
		"message": "success",
		"data": map[string]any{
			"init":    initData,
			"targets": targets,
			"meta":    doneData,
		},
	})
}

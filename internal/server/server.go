package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"RealityChecker/internal/service"
	"RealityChecker/internal/types"
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
		WriteTimeout:   5 * time.Minute, // 支持长耗时流式扫描
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
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = 5 * time.Minute
	}

	ts := &TargetServer{
		cfg:     cfg,
		service: svc,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", ts.handleHealth)
	mux.HandleFunc("/api/stats", ts.handleStats)
	mux.HandleFunc("/api/targets/smart", ts.handleTargetsSmart)
	mux.HandleFunc("/api/targets/stream", ts.handleTargetsStream)
	mux.HandleFunc("/api/targets/check", ts.handleTargetsCheck)
	mux.HandleFunc("/api/targets", ts.handleTargetsManage)
	mux.HandleFunc("/api/targets/", ts.handleTargetItemAction)
	mux.HandleFunc("/api/asns", ts.handleASNs)

	// 静态文件支持 (如果存在 web/dist 前端静态产物，直接托管)
	webDistPath := "web/dist"
	if fi, err := os.Stat(webDistPath); err == nil && fi.IsDir() {
		fs := http.FileServer(http.Dir(webDistPath))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			// 单页应用 SPA 路由回退
			filePath := filepath.Join(webDistPath, filepath.Clean(r.URL.Path))
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				http.ServeFile(w, r, filepath.Join(webDistPath, "index.html"))
				return
			}
			fs.ServeHTTP(w, r)
		})
	}

	handler := ts.corsMiddleware(ts.authMiddleware(mux))

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
	return s.httpServer.ListenAndServe()
}

// Shutdown 优雅关闭 HTTP 服务
func (s *TargetServer) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
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
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    200,
		"message": "Domain detected and saved successfully",
		"data":    rec,
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
			Keyword:  q.Get("keyword"),
			ASN:      q.Get("asn"),
			Country:  q.Get("country"),
			MinStars: minStars,
			IsActive: isActive,
			SortBy:   q.Get("sort_by"),
			Page:     page,
			PageSize: pageSize,
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

	if domain == "" {
		http.Error(w, `{"code": 400, "error": "Missing domain parameter"}`, http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPatch:
		var payload struct {
			IsActive bool `json:"is_active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "error": err.Error()})
			return
		}

		if err := s.service.UpdateTargetActive(domain, payload.IsActive); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 200, "message": "Updated successfully"})

	case http.MethodDelete:
		if err := s.service.DeleteTarget(domain); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 500, "error": err.Error()})
			return
		}
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

	return service.ProvisionRequest{
		IP:          q.Get("ip"),
		Limit:       limit,
		MinStars:    minStars,
		Fresh:       fresh,
		Country:     q.Get("country"),
		IPv4Only:    ipv4Only,
		IPv6Only:    ipv6Only,
		RequireNoCN: requireNoCN,
	}
}

func parseBool(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// handleTargetsStream 处理 SSE 流式返回
func (s *TargetServer) handleTargetsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	req := parseProvisionRequest(r)
	if req.IP == "" {
		http.Error(w, "Missing 'ip' query parameter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	emit := func(evt service.ProvisionEvent) error {
		dataBytes, err := json.Marshal(evt.Data)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Event, string(dataBytes))
		if err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	_ = s.service.StreamTargets(r.Context(), req, emit)
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


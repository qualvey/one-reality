package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"RealityChecker/internal/service"
)

// ServerConfig HTTP 服务配置
type ServerConfig struct {
	Addr           string        `json:"addr"`
	AllowedOrigins []string      `json:"allowed_origins"`
	ReadTimeout    time.Duration `json:"read_timeout"`
	WriteTimeout   time.Duration `json:"write_timeout"`
}

// DefaultServerConfig 返回默认配置
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:           ":8881",
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
	mux.HandleFunc("/api/targets/stream", ts.handleTargetsStream)
	mux.HandleFunc("/api/targets", ts.handleTargetsJSON)

	handler := ts.corsMiddleware(mux)

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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth 健康检查
func (s *TargetServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// parseProvisionRequest 解析 Query 参数为 ProvisionRequest
func parseProvisionRequest(r *http.Request) service.ProvisionRequest {
	q := r.URL.Query()

	limit := 5
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

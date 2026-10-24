package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"RealityChecker/internal/service"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

type mockResolver struct {
	asn      int
	prefixes []string
}

func (m *mockResolver) PrefixesForIP(ctx context.Context, ip string) (int, []string, error) {
	return m.asn, m.prefixes, nil
}

func (m *mockResolver) FetchPrefixes(ctx context.Context, resource string) ([]string, error) {
	return m.prefixes, nil
}

func setupTestServer(t *testing.T) (*TargetServer, *storage.TargetStore) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "server_test.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create target store: %v", err)
	}

	_ = store.UpsertTargets([]*types.TargetRecord{
		{
			Domain:        "target-a.test.com",
			ASN:           "AS12345",
			Country:       "US",
			IP:            "1.2.3.4",
			HandshakeMS:   28,
			CertDays:      88,
			StatusCode:    200,
			Stars:         5,
			LastCheckedAt: time.Now(),
		},
	})

	mockASN := &mockResolver{
		asn:      12345,
		prefixes: []string{"1.2.3.0/24"},
	}

	svc := service.NewProvisionService(store, nil, mockASN, nil)
	cfg := DefaultServerConfig()
	ts := NewTargetServer(cfg, svc)
	return ts, store
}

func TestServer_Health(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()

	ts.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var res map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if res["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", res["status"])
	}
}

func TestServer_CORS(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest(http.MethodOptions, "/api/targets", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()

	ts.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for options, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("expected CORS header *, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestServer_TargetsSmart(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	// 1. 缺失 IP 参数应返回 400
	req := httptest.NewRequest(http.MethodGet, "/api/targets/smart", nil)
	w := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing ip, got %d", w.Code)
	}

	// 2. 正常智能推荐 (命中同 ASN，权重置顶)
	req = httptest.NewRequest(http.MethodGet, "/api/targets/smart?ip=1.2.3.4&country=US", nil)
	w = httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Summary service.TargetSummaryInfo   `json:"summary"`
			Targets []service.RankedTargetItem  `json:"targets"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode json response: %v", err)
	}
	if resp.Code != 200 || len(resp.Data.Targets) == 0 {
		t.Fatalf("expected at least 1 target, got %v", resp)
	}

	firstTarget := resp.Data.Targets[0]
	if firstTarget.Domain != "target-a.test.com" {
		t.Errorf("expected domain target-a.test.com, got %s", firstTarget.Domain)
	}
	if firstTarget.MatchLevel != "same_asn" {
		t.Errorf("expected match_level same_asn for IP 1.2.3.4, got %s", firstTarget.MatchLevel)
	}
	if firstTarget.Score < 1000 {
		t.Errorf("expected score >= 1000 for same ASN, got %d", firstTarget.Score)
	}
}

func TestServer_TargetsManage(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	// 1. 查询列表 (无需 IP 参数)
	req := httptest.NewRequest(http.MethodGet, "/api/targets?page=1&page_size=10", nil)
	w := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Code int `json:"code"`
		Data struct {
			Items []*types.TargetRecord `json:"items"`
			Total int                   `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}
	if resp.Data.Total != 1 || len(resp.Data.Items) == 0 {
		t.Fatalf("expected 1 item, got %d", resp.Data.Total)
	}

	// 2. 更新状态 PATCH
	patchBody := strings.NewReader(`{"is_active": false}`)
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/targets/target-a.test.com", patchBody)
	patchW := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusOK {
		t.Fatalf("expected 200 for patch, got %d", patchW.Code)
	}

	// 3. 删除资产 DELETE
	delReq := httptest.NewRequest(http.MethodDelete, "/api/targets/target-a.test.com", nil)
	delW := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200 for delete, got %d", delW.Code)
	}
}

func TestServer_Stats(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Code int               `json:"code"`
		Data types.TargetStats `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if resp.Data.TotalTargets != 1 {
		t.Errorf("expected 1 target, got %d", resp.Data.TotalTargets)
	}
}


func TestServer_TargetsStream(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/targets/stream?ip=1.2.3.4&country=US&limit=1", nil)
	w := httptest.NewRecorder()

	ts.httpServer.Handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %s", w.Header().Get("Content-Type"))
	}

	body := w.Body.String()
	if !strings.Contains(body, "event: init") {
		t.Errorf("missing event: init in SSE output: %s", body)
	}
	if !strings.Contains(body, "event: target") {
		t.Errorf("missing event: target in SSE output: %s", body)
	}
	if !strings.Contains(body, "event: done") {
		t.Errorf("missing event: done in SSE output: %s", body)
	}

	// 逐行解析验证 SSE 协议规范
	scanner := bufio.NewScanner(strings.NewReader(body))
	var eventTypes []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			eventTypes = append(eventTypes, strings.TrimPrefix(line, "event: "))
		}
	}

	if len(eventTypes) < 3 {
		t.Fatalf("expected at least 3 events (init, target, done), got %v", eventTypes)
	}
}

func TestServer_AuthMiddleware(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "auth_test.db")
	store, _ := storage.NewTargetStore(dbPath)
	defer store.Close()

	svc := service.NewProvisionService(store, nil, &mockResolver{asn: 12345}, nil)
	cfg := DefaultServerConfig()
	cfg.APIToken = "secret123"
	ts := NewTargetServer(cfg, svc)

	// 1. 公开接口 /api/health 应允许匿名访问
	reqHealth := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	wHealth := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wHealth, reqHealth)
	if wHealth.Code != http.StatusOK {
		t.Errorf("expected 200 for /api/health without token, got %d", wHealth.Code)
	}

	// 2. /api/stats 未提供 token 应返回 401
	reqStatsNoToken := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	wStatsNoToken := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wStatsNoToken, reqStatsNoToken)
	if wStatsNoToken.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api/stats without token, got %d", wStatsNoToken.Code)
	}

	// 3. /api/stats 带错误的 Bearer token 应返回 401
	reqStatsWrongToken := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	reqStatsWrongToken.Header.Set("Authorization", "Bearer wrong-token")
	wStatsWrongToken := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wStatsWrongToken, reqStatsWrongToken)
	if wStatsWrongToken.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", wStatsWrongToken.Code)
	}

	// 4. /api/stats 带正确的 Bearer token 应放行 200
	reqStatsBearer := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	reqStatsBearer.Header.Set("Authorization", "Bearer secret123")
	wStatsBearer := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wStatsBearer, reqStatsBearer)
	if wStatsBearer.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Bearer token, got %d", wStatsBearer.Code)
	}

	// 5. /api/stats 带正确的 Query token (?token=secret123) 应放行 200
	reqStatsQuery := httptest.NewRequest(http.MethodGet, "/api/stats?token=secret123", nil)
	wStatsQuery := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wStatsQuery, reqStatsQuery)
	if wStatsQuery.Code != http.StatusOK {
		t.Errorf("expected 200 with valid query token, got %d", wStatsQuery.Code)
	}
}

func TestServer_StaticAssetFallback(t *testing.T) {
	ts, _ := setupTestServer(t)

	// 1. GET / 访问主页应返回 200 OK
	reqRoot := httptest.NewRequest(http.MethodGet, "/", nil)
	wRoot := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wRoot, reqRoot)
	if wRoot.Code != http.StatusOK {
		t.Errorf("expected 200 for root index, got %d", wRoot.Code)
	}

	// 2. GET /spa-route SPA 路由回退应返回 200 OK
	reqSPA := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	wSPA := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wSPA, reqSPA)
	if wSPA.Code != http.StatusOK {
		t.Errorf("expected 200 for SPA route fallback, got %d", wSPA.Code)
	}

	// 3. GET /api/nonexistent API 路由不应回退到 index.html，而应返回 404
	reqAPI := httptest.NewRequest(http.MethodGet, "/api/nonexistent", nil)
	wAPI := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wAPI, reqAPI)
	if wAPI.Code != http.StatusNotFound {
		t.Errorf("expected 404 for nonexistent API route, got %d", wAPI.Code)
	}
}

func TestServer_DefaultFilterAndPreferenceQuery(t *testing.T) {
	ts, store := setupTestServer(t)
	defer store.Close()

	// 1. 测试 GET /api/filter/default
	reqFilter := httptest.NewRequest(http.MethodGet, "/api/filter/default", nil)
	wFilter := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wFilter, reqFilter)

	if wFilter.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/filter/default, got %d", wFilter.Code)
	}
	var filterResp map[string]any
	if err := json.Unmarshal(wFilter.Body.Bytes(), &filterResp); err != nil {
		t.Fatalf("failed to decode filter json: %v", err)
	}
	if filterResp["code"] != float64(200) {
		t.Fatalf("expected code 200, got %v", filterResp["code"])
	}

	// 2. 插入测试数据测试偏好过滤
	_ = store.UpsertTargets([]*types.TargetRecord{
		{
			Domain:        "cdn.example.org",
			ASN:           "AS12345",
			Country:       "US",
			IP:            "1.2.3.5",
			HandshakeMS:   35,
			CertDays:      80,
			StatusCode:    200,
			IsCDN:         true,
			Stars:         3,
			LastCheckedAt: time.Now(),
		},
	})

	// 查询 require_no_cdn=1
	reqTargets := httptest.NewRequest(http.MethodGet, "/api/targets?require_no_cdn=1", nil)
	wTargets := httptest.NewRecorder()
	ts.httpServer.Handler.ServeHTTP(wTargets, reqTargets)

	if wTargets.Code != http.StatusOK {
		t.Fatalf("expected 200 for /api/targets, got %d", wTargets.Code)
	}
	var targetsResp map[string]any
	if err := json.Unmarshal(wTargets.Body.Bytes(), &targetsResp); err != nil {
		t.Fatalf("failed to decode targets json: %v", err)
	}
	dataMap := targetsResp["data"].(map[string]any)
	total := int(dataMap["total"].(float64))
	if total != 1 {
		t.Errorf("expected 1 non-CDN target, got %d", total)
	}
}


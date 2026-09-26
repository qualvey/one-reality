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

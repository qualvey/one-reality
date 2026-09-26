package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

func TestPatrolWatchdog_RunOnce(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "patrol_watchdog_test.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// 启动 TLS 测试服务器
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	parsedURL, _ := url.Parse(ts.URL)
	host, portStr, _ := parseHostPort(parsedURL.Host)
	port, _ := strconv.Atoi(portStr)

	// 写入一个需要巡检的资产记录
	rec := &types.TargetRecord{
		Domain:        "example-patrol.com",
		ASN:           "AS13335",
		Country:       "US",
		IP:            host,
		Port:          port,
		HandshakeMS:   150,
		CertDays:      60,
		StatusCode:    200,
		Stars:         5,
		IsActive:      true,
		FirstSeenAt:   time.Now().Add(-48 * time.Hour),
		LastCheckedAt: time.Now().Add(-25 * time.Hour), // 超过 24h 需要巡检
	}
	_ = store.UpsertTarget(rec)

	cfg := DefaultPatrolConfig()
	cfg.HighStarAge = 24 * time.Hour
	cfg.NormalStarAge = 72 * time.Hour

	var checkedEvents int
	events := PatrolEvents{
		OnTargetChecked: func(target *types.TargetRecord, success bool, ms int64, err error) {
			checkedEvents++
		},
	}

	watchdog := NewPatrolWatchdog(store, cfg, events)
	report, err := watchdog.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if report.TotalChecked != 1 {
		t.Errorf("expected 1 checked target, got %d", report.TotalChecked)
	}
	if checkedEvents != 1 {
		t.Errorf("expected 1 checked event, got %d", checkedEvents)
	}
}

func parseHostPort(hostPort string) (string, string, error) {
	for i := len(hostPort) - 1; i >= 0; i-- {
		if hostPort[i] == ':' {
			return hostPort[:i], hostPort[i+1:], nil
		}
	}
	return hostPort, "443", nil
}

func TestPatrolWatchdog_CheckTarget_Failure(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "patrol_fail_test.db")
	store, _ := storage.NewTargetStore(dbPath)
	defer store.Close()

	rec := &types.TargetRecord{
		Domain:        "unreachable-patrol-target.invalid",
		ASN:           "AS9999",
		Country:       "US",
		IP:            "127.0.0.1",
		Port:          59999, // 关闭的端口
		HandshakeMS:   100,
		CertDays:      30,
		Stars:         3,
		IsActive:      true,
		LastCheckedAt: time.Now().Add(-100 * time.Hour),
	}
	_ = store.UpsertTarget(rec)

	watchdog := NewPatrolWatchdog(store, DefaultPatrolConfig(), PatrolEvents{})
	success, _, _, _ := watchdog.CheckTarget(context.Background(), rec)
	if success {
		t.Errorf("expected check to fail for unreachable port")
	}

	// 验证 check_fail_count 递增
	targets, _ := store.GetAllTargets()
	if len(targets) != 1 || targets[0].CheckFailCount != 1 {
		t.Errorf("expected check_fail_count 1, got %#v", targets[0])
	}
}

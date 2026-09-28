package app

import (
	"path/filepath"
	"testing"

	"RealityChecker/internal/types"
)

func TestContainer_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_container.db")

	cfg := &types.Config{}
	cfg.Database.Driver = "sqlite"
	cfg.Database.SQLite.Path = dbPath

	container, err := NewContainer(ContainerOptions{
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}

	// 1. 测试 Config
	if container.Config() != cfg {
		t.Errorf("expected container.Config to match passed config")
	}

	// 2. 测试 Store 获取
	store, err := container.GetStore()
	if err != nil {
		t.Fatalf("failed to get store: %v", err)
	}
	if store == nil {
		t.Fatalf("store is nil")
	}

	// 再次获取应返回同一单例实例
	store2, err := container.GetStore()
	if err != nil || store2 != store {
		t.Errorf("store instance should be cached singleton")
	}

	// 3. 测试 Scanner 获取
	scannerEngine := container.GetScanner()
	if scannerEngine == nil {
		t.Errorf("scanner is nil")
	}
	if container.GetScanner() != scannerEngine {
		t.Errorf("scanner should be singleton")
	}

	// 4. 测试 ASNClient 获取
	asnCli := container.GetASNClient()
	if asnCli == nil {
		t.Errorf("asnClient is nil")
	}
	if container.GetASNClient() != asnCli {
		t.Errorf("asnClient should be singleton")
	}

	// 5. 测试 ProvisionService 获取
	svc, err := container.GetProvisionService()
	if err != nil {
		t.Fatalf("failed to get provision service: %v", err)
	}
	if svc == nil {
		t.Fatalf("provision service is nil")
	}

	// 6. 测试 Close 优雅关闭
	if err := container.Close(); err != nil {
		t.Errorf("container.Close failed: %v", err)
	}

	// 重复关闭应幂等且不报错
	if err := container.Close(); err != nil {
		t.Errorf("container.Close second call should not error: %v", err)
	}

	// 关闭后获取 store 应报错
	if _, err := container.GetStore(); err == nil {
		t.Errorf("expected error when getting store after container closed")
	}
}

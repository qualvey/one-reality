package core

import (
	"path/filepath"
	"testing"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

func TestDaemonScheduler_PickNextASN(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "daemon_test.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// 插入不同权重的 ASN
	_ = store.UpsertASNRecords([]*types.ASNRecord{
		{ASN: 13335, Priority: 100, ScanStatus: "pending"},
		{ASN: 16509, Priority: 90, ScanStatus: "pending"},
		{ASN: 10001, Priority: 10, ScanStatus: "pending"},
	})

	cfg := DefaultDaemonConfig()
	cfg.HighPriorityRatio = 1.0 // 强制选择高优队列测试

	daemon := NewDaemonScheduler(nil, store, nil, nil, cfg, DaemonEvents{})

	// 1. 应优先选择优先级最高的 13335
	asn1, err := daemon.PickNextASN()
	if err != nil || asn1 == nil {
		t.Fatalf("PickNextASN failed: %v", err)
	}
	if asn1.ASN != 13335 {
		t.Errorf("expected 13335, got %d", asn1.ASN)
	}

	// 2. 将 13335 与 16509 标记完成
	_ = store.UpdateASNStatus(13335, "completed", 0)
	_ = store.UpdateASNStatus(16509, "completed", 0)

	// 3. 高优队列已无待处理任务，应自动退化调度长尾队列的 10001
	asn2, err := daemon.PickNextASN()
	if err != nil || asn2 == nil {
		t.Fatalf("expected fallback to 10001, got err: %v", err)
	}
	if asn2.ASN != 10001 {
		t.Errorf("expected 10001, got %d", asn2.ASN)
	}

	// 4. 全部完成后应返回 nil
	_ = store.UpdateASNStatus(10001, "completed", 0)
	asn3, err := daemon.PickNextASN()
	if err != nil || asn3 != nil {
		t.Errorf("expected nil when all completed, got %#v (err: %v)", asn3, err)
	}
}

func TestDaemonScheduler_SingleASN(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "daemon_single.db")
	store, _ := storage.NewTargetStore(dbPath)
	defer store.Close()

	cfg := DefaultDaemonConfig()
	cfg.SingleASN = 31898 // Oracle

	daemon := NewDaemonScheduler(nil, store, nil, nil, cfg, DaemonEvents{})

	rec, err := daemon.PickNextASN()
	if err != nil || rec == nil {
		t.Fatalf("PickNextASN failed: %v", err)
	}
	if rec.ASN != 31898 {
		t.Errorf("expected 31898, got %d", rec.ASN)
	}
}

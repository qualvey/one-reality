package storage

import (
	"path/filepath"
	"testing"
	"time"

	"RealityChecker/internal/types"
)

func TestTargetStore_UpsertAndQueryByASN(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "targets.db")

	store, err := NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create TargetStore: %v", err)
	}
	defer store.Close()

	records := []*types.TargetRecord{
		{
			ASN:           "AS197196",
			Country:       "US",
			Domain:        "target1.com",
			IP:            "144.225.255.4",
			HandshakeMS:   320,
			CertDays:      80,
			StatusCode:    200,
			Stars:         4,
			LastCheckedAt: time.Now(),
		},
		{
			ASN:           "AS197196",
			Country:       "US",
			Domain:        "target2.org",
			IP:            "144.225.255.61",
			HandshakeMS:   350,
			CertDays:      90,
			StatusCode:    200,
			Stars:         4,
			LastCheckedAt: time.Now().Add(-10 * 24 * time.Hour), // 10 days old
		},
		{
			ASN:           "AS7203",
			Country:       "DE",
			Domain:        "de-target.de",
			IP:            "189.24.114.31",
			HandshakeMS:   180,
			CertDays:      60,
			StatusCode:    200,
			Stars:         5,
			LastCheckedAt: time.Now(),
		},
	}

	if err := store.UpsertTargets(records); err != nil {
		t.Fatalf("failed to upsert targets: %v", err)
	}

	if store.Count() != 3 {
		t.Errorf("expected 3 records, got %d", store.Count())
	}

	// Query fresh records for AS197196 within 7 days
	found, err := store.GetTargetsByASN("AS197196", "US", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("GetTargetsByASN failed: %v", err)
	}
	if len(found) != 1 || found[0].Domain != "target1.com" {
		t.Errorf("expected 1 fresh target (target1.com), got %v", found)
	}

	// Query all records for AS197196 without age limit
	allFound, err := store.GetTargetsByASN("197196", "US", 0)
	if err != nil {
		t.Fatalf("GetTargetsByASN failed: %v", err)
	}
	if len(allFound) != 2 {
		t.Errorf("expected 2 targets for AS197196, got %d", len(allFound))
	}
}

func TestTargetStore_ExportAndImport(t *testing.T) {
	tempDir := t.TempDir()
	dbPath1 := filepath.Join(tempDir, "db1.db")
	dbPath2 := filepath.Join(tempDir, "db2.db")
	exportPath := filepath.Join(tempDir, "export.json")

	store1, _ := NewTargetStore(dbPath1)
	_ = store1.UpsertTarget(&types.TargetRecord{
		ASN:    "AS1234",
		Domain: "export-test.com",
	})
	defer store1.Close()

	if err := store1.Export(exportPath); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	store2, _ := NewTargetStore(dbPath2)
	defer store2.Close()
	imported, err := store2.Import(exportPath)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}
	if imported != 1 || store2.Count() != 1 {
		t.Errorf("expected 1 imported target, got %d (count %d)", imported, store2.Count())
	}
}

func TestTargetStore_Checkpoints(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "targets_cp.db")

	store, err := NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create TargetStore: %v", err)
	}
	defer store.Close()

	taskKey := "AS37963_CN"

	// Initial check
	cps, err := store.GetCheckpoints(taskKey)
	if err != nil {
		t.Fatalf("GetCheckpoints failed: %v", err)
	}
	if len(cps) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(cps))
	}

	// Record partially completed CIDR with LastIP
	_ = store.RecordCheckpoint(taskKey, "47.115.0.0/17", "47.115.60.206", false)
	// Record fully completed CIDR
	_ = store.RecordCheckpoint(taskKey, "119.42.252.0/22", "119.42.255.254", true)

	cps, err = store.GetCheckpoints(taskKey)
	if err != nil {
		t.Fatalf("GetCheckpoints failed: %v", err)
	}
	if len(cps) != 2 {
		t.Fatalf("expected 2 checkpoints, got %d", len(cps))
	}

	p1 := cps["47.115.0.0/17"]
	if p1 == nil || p1.LastIP != "47.115.60.206" || p1.Completed {
		t.Errorf("unexpected p1: %#v", p1)
	}

	p2 := cps["119.42.252.0/22"]
	if p2 == nil || !p2.Completed {
		t.Errorf("unexpected p2: %#v", p2)
	}

	// Clear checkpoints
	_ = store.ClearCheckpoints(taskKey)
	cps, _ = store.GetCheckpoints(taskKey)
	if len(cps) != 0 {
		t.Errorf("expected 0 checkpoints after clear, got %d", len(cps))
	}
}

func TestTargetStore_ASNRegistry(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "asn_registry.db")

	store, err := NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create TargetStore: %v", err)
	}
	defer store.Close()

	// 1. 批量插入 ASN
	asns := []*types.ASNRecord{
		{
			ASN:        13335,
			Name:       "Cloudflare, Inc.",
			Country:    "US",
			TotalIPs:   1000000,
			Priority:   100,
			ScanStatus: "pending",
		},
		{
			ASN:        16509,
			Name:       "Amazon.com, Inc.",
			Country:    "US",
			TotalIPs:   5000000,
			Priority:   90,
			ScanStatus: "pending",
		},
		{
			ASN:        24940,
			Name:       "Hetzner Online GmbH",
			Country:    "DE",
			TotalIPs:   800000,
			Priority:   80,
			ScanStatus: "pending",
		},
	}

	if err := store.UpsertASNRecords(asns); err != nil {
		t.Fatalf("UpsertASNRecords failed: %v", err)
	}

	count, err := store.CountASNs("")
	if err != nil || count != 3 {
		t.Fatalf("expected 3 ASNs, got %d (err: %v)", count, err)
	}

	// 2. 取出最高优先级的 Pending ASN (应为 AS13335)
	nextASN, err := store.GetNextPendingASN(50)
	if err != nil || nextASN == nil {
		t.Fatalf("GetNextPendingASN failed: %v", err)
	}
	if nextASN.ASN != 13335 {
		t.Errorf("expected next ASN to be 13335, got %d", nextASN.ASN)
	}

	// 3. 更新为 scanning
	if err := store.UpdateASNStatus(13335, "scanning", 0); err != nil {
		t.Fatalf("UpdateASNStatus failed: %v", err)
	}

	// 4. 再取下一个 pending ASN (应为 AS16509)
	nextASN2, err := store.GetNextPendingASN(50)
	if err != nil || nextASN2 == nil {
		t.Fatalf("GetNextPendingASN failed: %v", err)
	}
	if nextASN2.ASN != 16509 {
		t.Errorf("expected next ASN to be 16509, got %d", nextASN2.ASN)
	}

	// 5. 将 13335 标记完成，增加命中资产数
	if err := store.UpdateASNStatus(13335, "completed", 15); err != nil {
		t.Fatalf("UpdateASNStatus completed failed: %v", err)
	}

	cf, err := store.GetASN(13335)
	if err != nil || cf == nil {
		t.Fatalf("GetASN failed: %v", err)
	}
	if cf.ScanStatus != "completed" || cf.SuccessTargetCount != 15 || cf.LastScannedAt.IsZero() {
		t.Errorf("unexpected cf record: %#v", cf)
	}

	// 6. 重置 scanning 状态
	_ = store.UpdateASNStatus(16509, "scanning", 0)
	if err := store.ResetScanningASNs(); err != nil {
		t.Fatalf("ResetScanningASNs failed: %v", err)
	}
	amz, _ := store.GetASN(16509)
	if amz.ScanStatus != "pending" {
		t.Errorf("expected 16509 status to be reset to pending, got %s", amz.ScanStatus)
	}

	// 7. 列表查询
	list, err := store.ListASNs("pending", 0, 10, 0)
	if err != nil || len(list) != 2 {
		t.Errorf("expected 2 pending ASNs, got %d", len(list))
	}
}

func TestTargetStore_PatrolAndLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "patrol.db")

	store, err := NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create TargetStore: %v", err)
	}
	defer store.Close()

	rec := &types.TargetRecord{
		Domain:        "patrol-test.com",
		ASN:           "AS13335",
		Country:       "US",
		IP:            "1.1.1.1",
		Port:          443,
		HandshakeMS:   100,
		CertDays:      90,
		StatusCode:    200,
		Stars:         5,
		IsActive:      true,
		FirstSeenAt:   time.Now().Add(-24 * time.Hour),
		LastCheckedAt: time.Now().Add(-25 * time.Hour),
	}
	if err := store.UpsertTarget(rec); err != nil {
		t.Fatalf("UpsertTarget failed: %v", err)
	}

	// 1. 查询待巡检列表
	toPatrol, err := store.GetTargetsForPatrol(4, 24*time.Hour, 10)
	if err != nil || len(toPatrol) != 1 {
		t.Fatalf("expected 1 target for patrol, got %d (err: %v)", len(toPatrol), err)
	}

	// 2. 模拟巡检成功
	err = store.UpdateTargetPatrolResult("patrol-test.com", "1.1.1.1", 80, 89, true, "")
	if err != nil {
		t.Fatalf("UpdateTargetPatrolResult success failed: %v", err)
	}

	list, _ := store.GetAllTargets()
	if len(list) != 1 || list[0].CheckFailCount != 0 || !list[0].IsActive {
		t.Errorf("unexpected target state after success: %#v", list[0])
	}
	// 加权延迟: (100 + 80) / 2 = 90
	if list[0].HandshakeMS != 90 {
		t.Errorf("expected smoothed handshake_ms 90, got %d", list[0].HandshakeMS)
	}

	// 3. 连续巡检失败 3 次触发下架与降星
	for i := 1; i <= 3; i++ {
		_ = store.UpdateTargetPatrolResult("patrol-test.com", "1.1.1.1", 0, 0, false, "connection refused")
	}

	list, _ = store.GetAllTargets()
	if list[0].CheckFailCount != 3 {
		t.Errorf("expected fail count 3, got %d", list[0].CheckFailCount)
	}
	if list[0].IsActive {
		t.Errorf("expected target to be deactivated after 3 failures")
	}
	// 5 星降了 3 次变成 2 星
	if list[0].Stars != 2 {
		t.Errorf("expected 2 stars, got %d", list[0].Stars)
	}

	// 4. 清理巡检日志
	time.Sleep(20 * time.Millisecond)
	deletedLogs, err := store.CleanExpiredPatrolLogs(0)
	if err != nil || deletedLogs < 4 {
		t.Errorf("expected at least 4 deleted logs, got %d (err: %v)", deletedLogs, err)
	}

	// 5. 执行 WAL Checkpoint
	if err := store.RunWALCheckpoint(); err != nil {
		t.Errorf("RunWALCheckpoint failed: %v", err)
	}
}



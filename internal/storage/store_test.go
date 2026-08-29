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
	cps, err := store.GetCompletedCIDRs(taskKey)
	if err != nil {
		t.Fatalf("GetCompletedCIDRs failed: %v", err)
	}
	if len(cps) != 0 {
		t.Errorf("expected 0 checkpoints, got %d", len(cps))
	}

	// Record completed CIDRs
	_ = store.RecordCompletedCIDR(taskKey, "8.134.244.0/23")
	_ = store.RecordCompletedCIDR(taskKey, "119.42.252.0/22")

	cps, err = store.GetCompletedCIDRs(taskKey)
	if err != nil {
		t.Fatalf("GetCompletedCIDRs failed: %v", err)
	}
	if len(cps) != 2 || !cps["8.134.244.0/23"] || !cps["119.42.252.0/22"] {
		t.Errorf("expected 2 checkpoints, got %v", cps)
	}

	// Clear checkpoints
	_ = store.ClearCheckpoints(taskKey)
	cps, _ = store.GetCompletedCIDRs(taskKey)
	if len(cps) != 0 {
		t.Errorf("expected 0 checkpoints after clear, got %d", len(cps))
	}
}


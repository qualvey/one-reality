package asn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"RealityChecker/internal/storage"
)

func setupTestStore(t *testing.T) (*storage.TargetStore, func()) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_registry.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	return store, func() { _ = store.Close() }
}

func TestRegistryManager_InitAndEnsureSeeded(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	mgr := NewRegistryManager(store)

	// 1. Initial count should be 0
	count, err := store.CountASNs("")
	if err != nil || count != 0 {
		t.Fatalf("expected 0 ASNs, got %d (err: %v)", count, err)
	}

	// 2. EnsureRegistrySeeded should initialize seed ASNs
	seeded, err := mgr.EnsureRegistrySeeded()
	if err != nil || seeded != len(SeedPopularASNs) {
		t.Fatalf("expected %d seeded ASNs, got %d (err: %v)", len(SeedPopularASNs), seeded, err)
	}

	// 3. Verify Cloudflare AS13335 is pre-marked as completed with priority 0
	cf, err := store.GetASN(13335)
	if err != nil || cf == nil {
		t.Fatalf("GetASN 13335 failed: %v", err)
	}
	if cf.Priority != 0 || cf.Country != "US" || cf.ScanStatus != "completed" {
		t.Errorf("unexpected Cloudflare ASN record: %#v", cf)
	}

	// Verify top VPS provider Hetzner AS24940 has priority 100
	hz, err := store.GetASN(24940)
	if err != nil || hz == nil {
		t.Fatalf("GetASN 24940 failed: %v", err)
	}
	if hz.Priority != 100 || hz.Country != "DE" {
		t.Errorf("unexpected Hetzner ASN record: %#v", hz)
	}

	// 4. Calling EnsureRegistrySeeded again should be a no-op
	seededAgain, err := mgr.EnsureRegistrySeeded()
	if err != nil || seededAgain != seeded {
		t.Errorf("expected %d on second call, got %d", seeded, seededAgain)
	}
}

func TestRegistryManager_ParseAndImportReader(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	mgr := NewRegistryManager(store)

	sampleData := `
# Example ASN dump file
AS13335 Cloudflare, Inc., US
AS24940 Hetzner Online GmbH, DE
AS12345 Test Provider, JP
99999
`
	imported, err := mgr.ParseAndImportReader(strings.NewReader(sampleData))
	if err != nil {
		t.Fatalf("ParseAndImportReader failed: %v", err)
	}
	if imported != 4 {
		t.Errorf("expected 4 imported ASNs, got %d", imported)
	}

	// Check ASN 12345
	rec, err := store.GetASN(12345)
	if err != nil || rec == nil {
		t.Fatalf("failed to find ASN 12345: %v", err)
	}
	if rec.Name != "Test Provider" || rec.Country != "JP" {
		t.Errorf("unexpected ASN 12345: %#v", rec)
	}

	// Check ASN 99999
	rec2, err := store.GetASN(99999)
	if err != nil || rec2 == nil {
		t.Fatalf("failed to find ASN 99999: %v", err)
	}
	if rec2.ASN != 99999 {
		t.Errorf("expected ASN 99999, got %d", rec2.ASN)
	}
}

func TestRegistryManager_SyncFromURLAndStats(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("AS1001 Test Cloud, US\nAS1002 Another Cloud, SG\n"))
	}))
	defer ts.Close()

	mgr := NewRegistryManager(store)
	imported, err := mgr.SyncFromURL(context.Background(), ts.URL)
	if err != nil {
		t.Fatalf("SyncFromURL failed: %v", err)
	}
	if imported != 2 {
		t.Errorf("expected 2 imported, got %d", imported)
	}

	stats, err := mgr.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats.TotalASNs != 2 || stats.PendingASNs != 2 {
		t.Errorf("unexpected stats: %#v", stats)
	}
}

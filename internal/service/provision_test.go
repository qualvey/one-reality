package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

type mockASNResolver struct {
	asn      int
	prefixes []string
	err      error
}

func (m *mockASNResolver) PrefixesForIP(ctx context.Context, ip string) (int, []string, error) {
	if m.err != nil {
		return 0, nil, m.err
	}
	return m.asn, m.prefixes, nil
}

func (m *mockASNResolver) FetchPrefixes(ctx context.Context, resource string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.prefixes, nil
}

func TestProvisionService_Validation(t *testing.T) {
	svc := NewProvisionService(nil, nil, nil, nil)

	// 1. 空 IP
	var events []ProvisionEvent
	err := svc.StreamTargets(context.Background(), ProvisionRequest{IP: ""}, func(evt ProvisionEvent) error {
		events = append(events, evt)
		return nil
	})
	if err == nil {
		t.Fatalf("expected error for empty ip, got nil")
	}
	if len(events) == 0 || events[0].Event != "error" {
		t.Fatalf("expected error event, got %v", events)
	}

	// 2. 非法 IP
	events = nil
	err = svc.StreamTargets(context.Background(), ProvisionRequest{IP: "999.999.999.999"}, func(evt ProvisionEvent) error {
		events = append(events, evt)
		return nil
	})
	if err == nil {
		t.Fatalf("expected error for invalid ip, got nil")
	}
}

func TestProvisionService_CacheHit(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_provision.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create target store: %v", err)
	}
	defer store.Close()

	// 预先写入 3 条优质资产 (AS13335, US)
	now := time.Now()
	err = store.UpsertTargets([]*types.TargetRecord{
		{
			Domain:        "cf1.cloudflare.com",
			ASN:           "AS13335",
			Country:       "US",
			IP:            "1.1.1.1",
			HandshakeMS:   35,
			CertDays:      80,
			StatusCode:    200,
			Stars:         5,
			LastCheckedAt: now,
		},
		{
			Domain:        "cf2.cloudflare.com",
			ASN:           "AS13335",
			Country:       "US",
			IP:            "1.0.0.1",
			HandshakeMS:   42,
			CertDays:      75,
			StatusCode:    200,
			Stars:         4,
			LastCheckedAt: now,
		},
		{
			Domain:        "cf3.cloudflare.com",
			ASN:           "AS13335",
			Country:       "US",
			IP:            "1.1.1.2",
			HandshakeMS:   50,
			CertDays:      60,
			StatusCode:    200,
			Stars:         3,
			LastCheckedAt: now,
		},
	})
	if err != nil {
		t.Fatalf("failed to seed test targets: %v", err)
	}

	mockASN := &mockASNResolver{
		asn:      13335,
		prefixes: []string{"1.1.1.0/24"},
	}

	svc := NewProvisionService(store, nil, mockASN, nil)

	var events []ProvisionEvent
	err = svc.StreamTargets(context.Background(), ProvisionRequest{
		IP:       "1.1.1.1",
		Limit:    2,
		MinStars: 4,
		Country:  "US",
	}, func(evt ProvisionEvent) error {
		events = append(events, evt)
		return nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 验证事件结构：应有 1 个 init，2 个 target (均为 cache)，1 个 done (reason: cache_full)
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	if events[0].Event != "init" {
		t.Errorf("first event should be 'init', got %s", events[0].Event)
	}

	initData, ok := events[0].Data.(InitEventData)
	if !ok || initData.ASN != "AS13335" {
		t.Errorf("invalid init data: %+v", events[0].Data)
	}

	// 检查两个 target 事件
	for i := 1; i <= 2; i++ {
		if events[i].Event != "target" {
			t.Errorf("event %d should be 'target', got %s", i, events[i].Event)
		}
		item, ok := events[i].Data.(TargetItem)
		if !ok || item.Source != "cache" || item.Stars < 4 {
			t.Errorf("target item invalid: %+v", events[i].Data)
		}
	}

	// 检查 done 事件
	if events[3].Event != "done" {
		t.Errorf("last event should be 'done', got %s", events[3].Event)
	}
	doneData, ok := events[3].Data.(DoneEventData)
	if !ok || doneData.Reason != "cache_full" || doneData.FromCache != 2 {
		t.Errorf("done data mismatch: %+v", events[3].Data)
	}
}

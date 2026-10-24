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

func TestProvisionService_GetSmartTargetsSummary(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_summary.db")
	store, _ := storage.NewTargetStore(dbPath)
	defer store.Close()

	// 记录一个断点
	_ = store.RecordCheckpoint("AS13335", "1.1.1.0/24", "1.1.1.50", false)

	mockASN := &mockASNResolver{
		asn:      13335,
		prefixes: []string{"1.1.1.0/24", "1.0.0.0/24"},
	}

	svc := NewProvisionService(store, nil, mockASN, nil)

	ranked, summary, err := svc.GetSmartTargets(context.Background(), ProvisionRequest{
		IP:      "1.1.1.1",
		Country: "US",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary == nil {
		t.Fatalf("expected non-nil summary")
	}

	if summary.ASN != "AS13335" {
		t.Errorf("expected AS13335, got %s", summary.ASN)
	}
	if summary.CIDRCount != 2 {
		t.Errorf("expected 2 CIDRs, got %d", summary.CIDRCount)
	}
	if summary.TotalIPs != 512 {
		t.Errorf("expected 512 total IPs, got %d", summary.TotalIPs)
	}
	if !summary.HasCheckpoint {
		t.Errorf("expected HasCheckpoint to be true")
	}
	if summary.LastCheckpointIP != "1.1.1.50" {
		t.Errorf("expected last checkpoint ip 1.1.1.50, got %s", summary.LastCheckpointIP)
	}
	if len(ranked) != 0 {
		t.Errorf("expected 0 cached targets, got %d", len(ranked))
	}
}

func TestProvisionService_CertRenewalLazyRecheck(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_cert_lazy.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("NewTargetStore failed: %v", err)
	}
	defer store.Close()

	// 准备两个同 ASN (AS13335) 的资产:
	// target1: 正常健康资产，证书充足 80 天
	// target2: 证书临期（剩余 20 天），且带有 TagCertRenewDelayed 标签
	expireNormal := time.Now().Add(80 * 24 * time.Hour).Truncate(time.Second)
	expirePending := time.Now().Add(20 * 24 * time.Hour).Truncate(time.Second)

	_ = store.UpsertTargets([]*types.TargetRecord{
		{
			Domain:        "healthy.cloudflare.com",
			ASN:           "AS13335",
			Country:       "US",
			IP:            "1.1.1.1",
			Port:          443,
			HandshakeMS:   30,
			CertDays:      80,
			CertExpireAt:  expireNormal,
			StatusCode:    200,
			Stars:         5,
			IsActive:      true,
			LastCheckedAt: time.Now(),
		},
		{
			Domain:        "risky.cloudflare.com",
			ASN:           "AS13335",
			Country:       "US",
			IP:            "1.0.0.1",
			Port:          443,
			HandshakeMS:   30,
			CertDays:      20,
			CertExpireAt:  expirePending,
			Tags:          []string{types.TagCertRenewDelayed},
			StatusCode:    200,
			Stars:         5,
			IsActive:      true,
			LastCheckedAt: time.Now(), // 刚刚检测过，测试冷却防抖下打分降权
		},
	})

	mockASN := &mockASNResolver{
		asn:      13335,
		prefixes: []string{"1.1.1.0/24"},
	}

	svc := NewProvisionService(store, nil, mockASN, nil)

	ranked, _, err := svc.GetSmartTargets(context.Background(), ProvisionRequest{
		IP:      "1.1.1.1",
		Country: "US",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("GetSmartTargets failed: %v", err)
	}

	if len(ranked) != 2 {
		t.Fatalf("expected 2 ranked targets, got %d", len(ranked))
	}

	// 验证健康资产排在第一名 (得益于无 TagCertRenewDelayed 惩罚且有 >30 天奖励)
	first := ranked[0]
	if first.Domain != "healthy.cloudflare.com" {
		t.Errorf("expected healthy.cloudflare.com to rank first, got %s", first.Domain)
	}
	if first.CertDays < 79 || first.CertDays > 81 {
		t.Errorf("expected ~80 cert days, got %d", first.CertDays)
	}
	if first.CertExpireAt == nil {
		t.Errorf("expected non-nil CertExpireAt")
	}

	// 验证临期未续期资产排在第二名，且扣除了对应分数
	second := ranked[1]
	if second.Domain != "risky.cloudflare.com" {
		t.Errorf("expected risky.cloudflare.com to rank second, got %s", second.Domain)
	}
	if second.Score >= first.Score {
		t.Errorf("expected risky target score (%d) to be strictly lower than healthy score (%d)", second.Score, first.Score)
	}
	if len(second.Tags) == 0 || second.Tags[0] != types.TagCertRenewDelayed {
		t.Errorf("expected TagCertRenewDelayed tag on second target, got %v", second.Tags)
	}
	if second.CertDays < 19 || second.CertDays > 21 {
		t.Errorf("expected ~20 cert days, got %d", second.CertDays)
	}
}

func TestProvisionService_GetSmartTargetsTieredRecall(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_tiered.db")
	store, err := storage.NewTargetStore(dbPath)
	if err != nil {
		t.Fatalf("NewTargetStore failed: %v", err)
	}
	defer store.Close()

	now := time.Now()
	// 插入三类资产：同ASN资产、同国家资产、全球优质资产
	_ = store.UpsertTargets([]*types.TargetRecord{
		{
			Domain:        "asn-match.example.com",
			ASN:           "AS61112",
			Country:       "JP",
			IP:            "154.83.93.1",
			Port:          443,
			HandshakeMS:   50,
			CertDays:      60,
			StatusCode:    200,
			Stars:         5,
			IsActive:      true,
			LastCheckedAt: now,
		},
		{
			Domain:        "country-match.example.com",
			ASN:           "AS2514",
			Country:       "JP",
			IP:            "203.0.113.1",
			Port:          443,
			HandshakeMS:   60,
			CertDays:      60,
			StatusCode:    200,
			Stars:         5,
			IsActive:      true,
			LastCheckedAt: now,
		},
		{
			Domain:        "global-match.example.com",
			ASN:           "AS15169",
			Country:       "US",
			IP:            "8.8.8.8",
			Port:          443,
			HandshakeMS:   70,
			CertDays:      60,
			StatusCode:    200,
			Stars:         5,
			IsActive:      true,
			LastCheckedAt: now,
		},
	})

	mockASN := &mockASNResolver{
		asn:      61112,
		prefixes: []string{"154.83.93.0/24"},
	}

	svc := NewProvisionService(store, nil, mockASN, nil)

	ranked, summary, err := svc.GetSmartTargets(context.Background(), ProvisionRequest{
		IP:          "154.83.93.117",
		Country:     "JP",
		Limit:       2,
		MinStars:    3,
		RequireNoCN: true,
	})
	if err != nil {
		t.Fatalf("GetSmartTargets failed: %v", err)
	}

	if summary == nil {
		t.Fatalf("expected non-nil summary")
	}
	if summary.SameASNHits != 1 {
		t.Errorf("expected 1 same ASN hit, got %d", summary.SameASNHits)
	}
	if len(ranked) != 2 {
		t.Fatalf("expected 2 ranked items due to limit=2, got %d", len(ranked))
	}
	if ranked[0].Domain != "asn-match.example.com" || ranked[0].MatchLevel != "same_asn" {
		t.Errorf("expected first to be same_asn, got %s (%s)", ranked[0].Domain, ranked[0].MatchLevel)
	}
	if ranked[1].Domain != "country-match.example.com" || ranked[1].MatchLevel != "same_country" {
		t.Errorf("expected second to be same_country, got %s (%s)", ranked[1].Domain, ranked[1].MatchLevel)
	}
}



package batch

import (
	"testing"
	"time"

	"RealityChecker/internal/types"
)

func TestBatchManager_SortByRecommendationStars(t *testing.T) {
	bm := NewManager(nil)

	res1 := &types.DetectionResult{
		Domain:   "target1.com",
		Suitable: true,
		TLS: &types.TLSResult{
			SupportsTLS13: true,
			SupportsX25519: true,
			SupportsHTTP2: true,
			HandshakeTime: 300 * time.Millisecond,
		},
		SNI: &types.SNIResult{SNIMatch: true},
	}

	res2 := &types.DetectionResult{
		Domain:   "target2.com",
		Suitable: true,
		TLS: &types.TLSResult{
			SupportsTLS13: true,
			SupportsX25519: true,
			SupportsHTTP2: true,
			HandshakeTime: 100 * time.Millisecond,
		},
		SNI: &types.SNIResult{SNIMatch: true},
		CDN: &types.CDNResult{IsCDN: false, IsHotWebsite: false},
		Certificate: &types.CertificateResult{Valid: true, DaysUntilExpiry: 90},
	}

	list := []*types.DetectionResult{res2, res1}
	bm.SortByRecommendationStars(list)

	// res1 拥有较少星级，排在前面；res2 拥有更多星级，排在后面
	if list[0].Domain != "target1.com" || list[1].Domain != "target2.com" {
		t.Errorf("expected target1.com then target2.com, got %s then %s", list[0].Domain, list[1].Domain)
	}

	stars1 := bm.calculateStars(res1)
	stars2 := bm.calculateStars(res2)
	if stars1 >= stars2 {
		t.Errorf("expected stars1 (%d) < stars2 (%d)", stars1, stars2)
	}
}

func TestBatchManager_GenerateBatchReport_FilterIntegration(t *testing.T) {
	cfg := &types.Config{
		RealityFilter: types.RealityFilterConfig{
			RequireNoCDN: true,
		},
	}
	bm := NewManager(cfg)

	normalTarget := &types.DetectionResult{
		Domain:   "good.com",
		Suitable: true,
		TLS: &types.TLSResult{
			SupportsTLS13: true,
			SupportsX25519: true,
			SupportsHTTP2: true,
		},
		SNI: &types.SNIResult{SNIMatch: true},
		CDN: &types.CDNResult{IsCDN: false},
	}

	cdnTarget := &types.DetectionResult{
		Domain:   "cdn.com",
		Suitable: true,
		TLS: &types.TLSResult{
			SupportsTLS13: true,
			SupportsX25519: true,
			SupportsHTTP2: true,
		},
		SNI: &types.SNIResult{SNIMatch: true},
		CDN: &types.CDNResult{IsCDN: true, CDNProvider: "Cloudflare"},
	}

	now := time.Now()
	report := bm.generateBatchReport([]*types.DetectionResult{normalTarget, cdnTarget}, now, now.Add(time.Second))

	// 经过 core.FilterTarget 校验后，仅 non-CDN 目标属于符合用户偏好的 Suitable 目标
	if report.Statistics.SuitableDomains != 1 {
		t.Errorf("expected 1 suitable domain, got %d", report.Statistics.SuitableDomains)
	}
}

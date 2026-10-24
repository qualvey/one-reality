package core

import (
	"context"
	"testing"
	"time"

	"RealityChecker/internal/types"
)

func TestPipelineProfiles(t *testing.T) {
	cfg := &types.Config{}

	// 1. 测试默认创建为 ProfileStandard
	pStd := NewPipeline(nil, cfg)
	if pStd.Profile() != ProfileStandard {
		t.Errorf("expected ProfileStandard, got %v", pStd.Profile())
	}
	if len(pStd.GetStages()) != 8 {
		t.Errorf("expected 8 stages in ProfileStandard, got %d", len(pStd.GetStages()))
	}
	if !pStd.HasStage("status_check") {
		t.Errorf("expected status_check stage in ProfileStandard")
	}

	// 2. 测试 Fast Profile (海量网段吞吐优先)
	pFast := NewPipelineWithProfile(nil, cfg, ProfileFast)
	if pFast.Profile() != ProfileFast {
		t.Errorf("expected ProfileFast, got %v", pFast.Profile())
	}
	stagesFast := pFast.GetStages()
	if len(stagesFast) != 3 {
		t.Errorf("expected 3 stages in ProfileFast, got %d", len(stagesFast))
	}
	if pFast.HasStage("status_check") {
		t.Errorf("did not expect status_check stage in ProfileFast")
	}
	if !pFast.HasStage("blocked") || !pFast.HasStage("comprehensive_tls") || !pFast.HasStage("hot_website") {
		t.Errorf("expected blocked, comprehensive_tls, hot_website in ProfileFast, got %v", pFast.StageNames())
	}

	// 3. 测试动态切换 Profile
	pFast.SetProfile(ProfileStandard)
	if pFast.Profile() != ProfileStandard {
		t.Errorf("expected ProfileStandard after SetProfile, got %v", pFast.Profile())
	}
	if len(pFast.GetStages()) != 8 {
		t.Errorf("expected 8 stages after switching to ProfileStandard, got %d", len(pFast.GetStages()))
	}
}

func TestPipelineDynamicStageToggle(t *testing.T) {
	cfg := &types.Config{}
	p := NewPipelineWithProfile(nil, cfg, ProfileFast)

	if p.HasStage("redirect") {
		t.Errorf("redirect should not exist in fast profile initially")
	}

	// 动态启用 redirect
	p.EnableStage("redirect", true)
	if !p.HasStage("redirect") {
		t.Errorf("redirect should be enabled")
	}
	if len(p.GetStages()) != 4 {
		t.Errorf("expected 4 stages after adding redirect, got %d", len(p.GetStages()))
	}

	// 动态禁用 redirect
	p.EnableStage("redirect", false)
	if p.HasStage("redirect") {
		t.Errorf("redirect should be disabled")
	}
	if len(p.GetStages()) != 3 {
		t.Errorf("expected 3 stages after removing redirect, got %d", len(p.GetStages()))
	}
}

type dummyStage struct {
	name     string
	priority int
	executed bool
}

func (d *dummyStage) Name() string { return d.name }
func (d *dummyStage) Priority() int { return d.priority }
func (d *dummyStage) CanEarlyExit() bool { return false }
func (d *dummyStage) Execute(ctx *types.PipelineContext) error {
	d.executed = true
	return nil
}

func TestPipelineCustomStages(t *testing.T) {
	d1 := &dummyStage{name: "stage1", priority: 10}
	d2 := &dummyStage{name: "stage2", priority: 5}

	p := NewPipelineWithOptions(nil, nil, WithStages(d1, d2))
	stages := p.GetStages()
	if len(stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(stages))
	}
	// 验证按优先级排序: priority 5 < 10
	if stages[0].Name() != "stage2" || stages[1].Name() != "stage1" {
		t.Errorf("stages not sorted by priority: %s, %s", stages[0].Name(), stages[1].Name())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, err := p.Execute(ctx, "example.com")
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if res.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", res.Domain)
	}
	if !d1.executed || !d2.executed {
		t.Errorf("stages were not executed: d1=%v, d2=%v", d1.executed, d2.executed)
	}
}

func TestEngineProfileIntegration(t *testing.T) {
	cfg := &types.Config{}
	engine := NewEngineWithProfile(cfg, ProfileFast)
	if engine.Profile() != ProfileFast {
		t.Errorf("expected engine ProfileFast, got %v", engine.Profile())
	}

	engine.SetProfile(ProfileStandard)
	if engine.Profile() != ProfileStandard {
		t.Errorf("expected engine ProfileStandard, got %v", engine.Profile())
	}

	pipeline := engine.GetPipeline()
	if pipeline == nil {
		t.Fatalf("expected pipeline not to be nil")
	}
	if pipeline.Profile() != ProfileStandard {
		t.Errorf("pipeline profile mismatch: %v", pipeline.Profile())
	}
}

func TestEvaluateSuitabilityDecoupledFromQueryPreferences(t *testing.T) {
	cfg := &types.Config{
		RealityFilter: types.RealityFilterConfig{
			RequireNoDefaultPage: true,
			ExcludeStatus:        []int{403, 404},
		},
	}
	p := NewPipeline(nil, cfg)

	// 1. 测试默认页面 (虽然启用了 RequireNoDefaultPage，但协议硬基线应判定适合落库)
	resDefault := &types.DetectionResult{
		Domain: "nginx-default.org",
		Network: &types.NetworkResult{
			Accessible:        true,
			StatusCode:        200,
			IsDefaultPage:     true,
			DefaultPageType:   "nginx",
			DefaultPageReason: "默认欢迎页",
		},
		TLS: &types.TLSResult{
			SupportsTLS13:  true,
			SupportsX25519: true,
			SupportsHTTP2:  true,
		},
		Certificate: &types.CertificateResult{
			Valid:            true,
			DaysUntilExpiry:  30,
		},
		SNI: &types.SNIResult{
			SupportsSNI: true,
			SNIMatch:    true,
		},
	}

	p.evaluateSuitability(resDefault)
	if !resDefault.Suitable {
		t.Errorf("expected resDefault.Suitable to be true for ingestion, got false (err: %v)", resDefault.Error)
	}

	// 验证在阶段二偏好过滤 FilterTarget 中依然被正确拦截
	passed, reason := FilterTarget(resDefault, cfg.RealityFilter)
	if passed {
		t.Errorf("expected FilterTarget to reject default page during query filtering")
	}
	if reason == "" {
		t.Errorf("expected non-empty reject reason for default page")
	}

	// 2. 测试排除状态码 (403 依然判定适合落库，但 StatusCodeCategory 被打标为 Excluded)
	res403 := &types.DetectionResult{
		Domain: "forbidden.example.com",
		Network: &types.NetworkResult{
			Accessible: true,
			StatusCode: 403,
		},
		TLS: &types.TLSResult{
			SupportsTLS13:  true,
			SupportsX25519: true,
			SupportsHTTP2:  true,
		},
		Certificate: &types.CertificateResult{
			Valid:            true,
			DaysUntilExpiry:  30,
		},
		SNI: &types.SNIResult{
			SupportsSNI: true,
			SNIMatch:    true,
		},
	}

	p.evaluateSuitability(res403)
	if !res403.Suitable {
		t.Errorf("expected res403.Suitable to be true for ingestion, got false (err: %v)", res403.Error)
	}
	if res403.StatusCodeCategory != types.StatusCodeCategoryExcluded {
		t.Errorf("expected StatusCodeCategoryExcluded, got %v", res403.StatusCodeCategory)
	}

	// 验证阶段二偏好过滤拦截 403 状态码
	passed403, reason403 := FilterTarget(res403, cfg.RealityFilter)
	if passed403 {
		t.Errorf("expected FilterTarget to reject status code 403")
	}
	if reason403 == "" {
		t.Errorf("expected non-empty reject reason for 403")
	}
}

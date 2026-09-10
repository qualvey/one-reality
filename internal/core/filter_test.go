package core

import (
	"testing"
	"time"

	"RealityChecker/internal/types"
)

func TestFilterTarget_HardRequirement(t *testing.T) {
	filter := types.RealityFilterConfig{
		MaxHandshakeMS: 500,
	}

	unsuitableTarget := &types.DetectionResult{
		Domain:   "broken.example.com",
		Suitable: false,
	}

	passed, _ := FilterTarget(unsuitableTarget, filter)
	if passed {
		t.Errorf("expected unsuitable target to fail FilterTarget")
	}
}

func TestFilterTarget_IncludeAndExcludeSuffixes(t *testing.T) {
	filter := types.RealityFilterConfig{
		IncludeSuffixes: []string{".com", ".org"},
		ExcludeSuffixes: []string{".xyz"},
	}

	validTarget := &types.DetectionResult{
		Domain:   "portal.example.com",
		Suitable: true,
	}
	if passed, reason := FilterTarget(validTarget, filter); !passed {
		t.Errorf("expected .com to pass include filter, failed: %s", reason)
	}

	notIncludedTarget := &types.DetectionResult{
		Domain:   "node.de",
		Suitable: true,
	}
	if passed, _ := FilterTarget(notIncludedTarget, filter); passed {
		t.Errorf("expected .de to be rejected because it is not in include_suffixes")
	}

	excludedTarget := &types.DetectionResult{
		Domain:   "test.xyz",
		Suitable: true,
	}
	if passed, _ := FilterTarget(excludedTarget, filter); passed {
		t.Errorf("expected .xyz to be rejected by exclude filter")
	}
}

func TestFilterTarget_LatencyAndStatusCode(t *testing.T) {
	filter := types.RealityFilterConfig{
		MaxHandshakeMS: 300,
		ExcludeStatus:  []int{302, 404, 500},
	}

	fastTarget := &types.DetectionResult{
		Domain:   "fast.example.com",
		Suitable: true,
		TLS: &types.TLSResult{
			HandshakeTime: 150 * time.Millisecond,
		},
		Network: &types.NetworkResult{
			Accessible: true,
			StatusCode: 200,
		},
	}
	if passed, reason := FilterTarget(fastTarget, filter); !passed {
		t.Errorf("expected fastTarget to pass, failed: %s", reason)
	}

	slowTarget := &types.DetectionResult{
		Domain:   "slow.example.com",
		Suitable: true,
		TLS: &types.TLSResult{
			HandshakeTime: 450 * time.Millisecond,
		},
		Network: &types.NetworkResult{
			Accessible: true,
			StatusCode: 200,
		},
	}
	if passed, _ := FilterTarget(slowTarget, filter); passed {
		t.Errorf("expected slowTarget (450ms > 300ms) to fail")
	}

	redirectTarget := &types.DetectionResult{
		Domain:   "redirect.example.com",
		Suitable: true,
		TLS: &types.TLSResult{
			HandshakeTime: 120 * time.Millisecond,
		},
		Network: &types.NetworkResult{
			Accessible: true,
			StatusCode: 302,
		},
	}
	if passed, _ := FilterTarget(redirectTarget, filter); passed {
		t.Errorf("expected redirectTarget (status 302) to be excluded")
	}
}

func TestFilterPool(t *testing.T) {
	pool := []*types.DetectionResult{
		{
			Domain:   "a.com",
			Suitable: true,
			TLS:      &types.TLSResult{HandshakeTime: 100 * time.Millisecond},
			Network:  &types.NetworkResult{Accessible: true, StatusCode: 200},
		},
		{
			Domain:   "b.xyz",
			Suitable: true,
			TLS:      &types.TLSResult{HandshakeTime: 120 * time.Millisecond},
			Network:  &types.NetworkResult{Accessible: true, StatusCode: 200},
		},
		{
			Domain:   "c.com",
			Suitable: false,
		},
	}

	filter := types.RealityFilterConfig{
		ExcludeSuffixes: []string{".xyz"},
	}

	results := FilterPool(pool, filter)
	if len(results) != 1 || results[0].Domain != "a.com" {
		t.Errorf("unexpected FilterPool result count: %d", len(results))
	}
}

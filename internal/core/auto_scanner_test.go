package core

import (
	"context"
	"errors"
	"testing"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

func TestAutoScanner_EmptyCIDRs(t *testing.T) {
	scanner := NewAutoScanner(nil, nil, nil, AutoScanConfig{
		CIDRs: []string{},
	}, AutoScanEvents{})

	_, err := scanner.Run(context.Background())
	if !errors.Is(err, ErrNoCIDRsProvided) {
		t.Fatalf("expected ErrNoCIDRsProvided, got %v", err)
	}
}

func TestAutoScanner_CalculateRemainingIPs(t *testing.T) {
	cidrs := []string{
		"192.168.1.0/24",
		"10.0.0.0/16",
	}

	// 1. 无断点: 256 + 65536 = 65792
	total := CalculateRemainingIPs(cidrs, nil)
	if total != 65792 {
		t.Errorf("expected 65792, got %d", total)
	}

	// 2. 一个网段完成
	checkpoints := map[string]*storage.CheckpointRecord{
		"192.168.1.0/24": {
			CIDR:      "192.168.1.0/24",
			Completed: true,
		},
	}
	remaining := CalculateRemainingIPs(cidrs, checkpoints)
	if remaining != 65536 {
		t.Errorf("expected 65536, got %d", remaining)
	}
}

func TestPrioritizeCIDRsByIP(t *testing.T) {
	cidrs := []string{
		"10.0.0.0/8",
		"192.0.0.0/8",
		"192.0.2.0/24",
		"2001:db8::/32",
	}

	got := PrioritizeCIDRsByIP(cidrs, "192.0.2.10")
	want := []string{
		"192.0.0.0/8",
		"192.0.2.0/24",
		"10.0.0.0/8",
		"2001:db8::/32",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d CIDRs, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("CIDR %d: expected %s, got %s", i, want[i], got[i])
		}
	}
}

func TestAutoScanner_InitialResultsLoaded(t *testing.T) {
	initial := []*types.DetectionResult{
		{Domain: "example.com", Suitable: true},
		{Domain: "test.org", Suitable: true},
	}

	scanner := NewAutoScanner(nil, nil, nil, AutoScanConfig{
		CIDRs:          []string{"1.2.3.4"},
		InitialResults: initial,
	}, AutoScanEvents{})

	if len(scanner.suitableResults) != 2 {
		t.Errorf("expected 2 initial suitable results, got %d", len(scanner.suitableResults))
	}
	if !scanner.domainSet["example.com"] || !scanner.domainSet["test.org"] {
		t.Errorf("domainSet missing initial results")
	}
}

func TestAutoScanner_CandidateRejectedEvent(t *testing.T) {
	rejectedReported := false
	var reportedReason string

	events := AutoScanEvents{
		OnCandidateRejected: func(ip string, domain string, reason string) {
			rejectedReported = true
			reportedReason = reason
		},
	}

	filter := types.RealityFilterConfig{
		ExcludeSuffixes: []string{".top"},
	}

	scanner := NewAutoScanner(nil, nil, nil, AutoScanConfig{
		CIDRs:   []string{"127.0.0.1"},
		Filter:  filter,
		Verbose: true,
	}, events)

	// 模拟候选结果进入过滤阶段
	res := &types.DetectionResult{
		Domain:   "bad-node.top",
		Suitable: true,
	}

	passed, reason := FilterTarget(res, scanner.config.Filter)
	if passed {
		t.Fatalf("expected target with .top to be rejected")
	}

	if scanner.events.OnCandidateRejected != nil {
		scanner.events.OnCandidateRejected("1.2.3.4", res.Domain, reason)
	}

	if !rejectedReported {
		t.Errorf("expected OnCandidateRejected to be called")
	}
	if reportedReason == "" {
		t.Errorf("expected non-empty rejection reason")
	}
}

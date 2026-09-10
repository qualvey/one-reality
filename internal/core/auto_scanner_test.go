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

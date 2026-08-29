package cmd

import (
	"testing"

	"RealityChecker/internal/storage"
)

func TestParseDomains(t *testing.T) {
	input := "apple.com google.com apple.com invalid..domain test.org"
	valid, invalid, duplicates := parseDomains(input)

	if len(valid) != 3 {
		t.Fatalf("expected 3 valid domains, got %d (%v)", len(valid), valid)
	}
	if len(duplicates) != 1 || duplicates[0] != "apple.com" {
		t.Fatalf("expected 1 duplicate (apple.com), got %v", duplicates)
	}
	if len(invalid) != 1 || invalid[0] != "invalid..domain" {
		t.Fatalf("expected 1 invalid (invalid..domain), got %v", invalid)
	}
}

func TestCalculateRemainingIPs(t *testing.T) {
	cidrs := []string{
		"192.168.1.0/24",
		"47.115.0.0/17",
	}

	// 1. No checkpoints: 256 + 32768 = 33024
	total := CalculateRemainingIPs(cidrs, nil)
	if total != 33024 {
		t.Errorf("expected 33024, got %d", total)
	}

	// 2. 192.168.1.0/24 completed: 0 + 32768 = 32768
	checkpoints := map[string]*storage.CheckpointRecord{
		"192.168.1.0/24": {
			CIDR:      "192.168.1.0/24",
			Completed: true,
		},
		"47.115.0.0/17": {
			CIDR:      "47.115.0.0/17",
			LastIP:    "47.115.0.0", // 1 IP scanned, 32767 remaining
			Completed: false,
		},
	}
	remaining := CalculateRemainingIPs(cidrs, checkpoints)
	if remaining != 32767 {
		t.Errorf("expected 32767, got %d", remaining)
	}
}


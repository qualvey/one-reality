package cmd

import (
	"testing"
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

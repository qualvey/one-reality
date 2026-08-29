package config

import (
	"os"
	"path/filepath"
	"testing"

	"RealityChecker/internal/types"
)

func TestShouldExcludeDomain_ConfigDriven(t *testing.T) {
	filter := types.RealityFilterConfig{
		ExcludeDomains:  []string{"private.example.com", "localhost"},
		ExcludeSuffixes: []string{".internal", ".local", ".arpa"},
		ExcludePatterns: []string{"kubernetes", "fake certificate"},
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"private.example.com", true},
		{"localhost", true},
		{"demo.internal", true},
		{"node.local", true},
		{"1.0.0.127.in-addr.arpa", true},
		{"kubernetes-ingress.example.com", true},
		{"some-fake certificate-domain.com", true},
		{"*.wildcard.com", true},
		{"192.168.1.1", true},
		{"good.example.com", false},
		{"apple.com", false},
		{"microsoft.com", false},
	}

	for _, tt := range tests {
		got := ShouldExcludeDomain(tt.domain, filter)
		if got != tt.want {
			t.Errorf("ShouldExcludeDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestLoadExcludeRulesFromFile(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "rules.txt")

	content := `# Test rules
include_suffixes:
  .com
  .org

exclude_suffixes:
  .custom
  .testlab

exclude_domains:
  test.domain.com

exclude_patterns:
  mock-k8s

exclude_status:
  302
  404
`
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test rules file: %v", err)
	}

	domains, suffixes, patterns, statusCodes, includeSuffixes, err := LoadExcludeRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("LoadExcludeRulesFromFile failed: %v", err)
	}

	if len(domains) != 1 || domains[0] != "test.domain.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
	if len(suffixes) != 2 || suffixes[0] != ".custom" || suffixes[1] != ".testlab" {
		t.Errorf("unexpected suffixes: %v", suffixes)
	}
	if len(patterns) != 1 || patterns[0] != "mock-k8s" {
		t.Errorf("unexpected patterns: %v", patterns)
	}
	if len(statusCodes) != 2 || statusCodes[0] != 302 || statusCodes[1] != 404 {
		t.Errorf("unexpected statusCodes: %v", statusCodes)
	}
	if len(includeSuffixes) != 2 || includeSuffixes[0] != ".com" || includeSuffixes[1] != ".org" {
		t.Errorf("unexpected includeSuffixes: %v", includeSuffixes)
	}
}

func TestShouldExcludeStatusCode(t *testing.T) {
	filter := types.RealityFilterConfig{
		ExcludeStatus: []int{301, 302, 404, 500},
	}

	if !ShouldExcludeStatusCode(302, filter) {
		t.Errorf("expected 302 to be excluded")
	}
	if !ShouldExcludeStatusCode(404, filter) {
		t.Errorf("expected 404 to be excluded")
	}
	if ShouldExcludeStatusCode(200, filter) {
		t.Errorf("expected 200 to NOT be excluded")
	}
}

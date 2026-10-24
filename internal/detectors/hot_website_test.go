package detectors

import (
	"testing"
)

func TestHotWebsiteEmbeddedFallback(t *testing.T) {
	stage := NewHotWebsiteStage()

	// 热门大站列表中包含 google.com / youtube.com / apple.com 等
	testCases := []struct {
		domain string
		expect bool
	}{
		{"google.com", true},
		{"www.google.com", true},
		{"mail.google.com", true},
		{"apple.com", true},
		{"sub.apple.com", true},
		{"totally-random-unknown-domain-123456.com", false},
	}

	for _, tc := range testCases {
		res := stage.detectHotWebsite(tc.domain)
		if res != tc.expect {
			t.Errorf("detectHotWebsite(%q) = %v, want %v", tc.domain, res, tc.expect)
		}
	}
}

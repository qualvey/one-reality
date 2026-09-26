package scanner

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"
)

func TestExtractCertDomain(t *testing.T) {
	tests := []struct {
		name     string
		leaf     *x509.Certificate
		expected string
	}{
		{
			name:     "Nil leaf",
			leaf:     nil,
			expected: "",
		},
		{
			name: "Modern cert with empty CN but valid DNSNames",
			leaf: &x509.Certificate{
				Subject:  pkix.Name{CommonName: ""},
				DNSNames: []string{"api.example.com", "cdn.example.com"},
			},
			expected: "api.example.com",
		},
		{
			name: "Wildcard in DNSNames with apex domain present",
			leaf: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "*.example.com"},
				DNSNames: []string{"*.example.com", "example.com"},
			},
			expected: "example.com",
		},
		{
			name: "Wildcard only in DNSNames",
			leaf: &x509.Certificate{
				Subject:  pkix.Name{CommonName: ""},
				DNSNames: []string{"*.service.net"},
			},
			expected: "service.net",
		},
		{
			name: "Fallback to CommonName",
			leaf: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "portal.internal.org"},
				DNSNames: nil,
			},
			expected: "portal.internal.org",
		},
		{
			name: "Fallback to wildcard CommonName",
			leaf: &x509.Certificate{
				Subject:  pkix.Name{CommonName: "*.mycloud.io"},
				DNSNames: nil,
			},
			expected: "mycloud.io",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractCertDomain(tc.leaf)
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestScanTLSProbe_ClosedPort(t *testing.T) {
	s := NewScanner()
	defer s.Close()

	host := Host{
		IP:   net.ParseIP("127.0.0.1"),
		Type: HostTypeIP,
	}

	res, probe := s.ScanTLSProbe(context.Background(), host, 65432, 1, false)
	if res != nil {
		t.Errorf("expected nil ScanResult on closed port, got %v", res)
	}
	if probe == nil {
		t.Fatalf("expected non-nil ProbeResult")
	}
	if probe.Success {
		t.Errorf("expected probe.Success to be false")
	}
	if probe.FailureReason == "" {
		t.Errorf("expected non-empty probe.FailureReason")
	}
}

type mockRateLimiter struct {
	acquireCount int
	releaseCount int
	reportCount  int
}

func (m *mockRateLimiter) Acquire(ctx context.Context) error {
	m.acquireCount++
	return nil
}

func (m *mockRateLimiter) Release() {
	m.releaseCount++
}

func (m *mockRateLimiter) ReportProbe(duration time.Duration, isTimeout bool, isSuccess bool) {
	m.reportCount++
}

func TestScanCIDRStreamAdaptive_LimiterIntegration(t *testing.T) {
	s := NewScanner()
	defer s.Close()

	limiter := &mockRateLimiter{}
	outChan := make(chan *ScanResult, 10)

	// 扫描单个 IP 127.0.0.1
	s.ScanCIDRStreamAdaptive(
		context.Background(),
		"127.0.0.1/32",
		"",
		65432,
		1,
		1,
		false,
		limiter,
		outChan,
		nil,
		nil,
	)

	close(outChan)

	if limiter.acquireCount != 1 {
		t.Errorf("expected 1 Acquire call, got %d", limiter.acquireCount)
	}
	if limiter.releaseCount != 1 {
		t.Errorf("expected 1 Release call, got %d", limiter.releaseCount)
	}
	if limiter.reportCount != 1 {
		t.Errorf("expected 1 ReportProbe call, got %d", limiter.reportCount)
	}
}



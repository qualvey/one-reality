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

func TestIsValidPublicDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"", false},
		{"localhost", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"ubuntu", false},
		{"internal-host", false},
		{"server.local", false},
		{"node.lan", false},
		{"cluster.internal", false},
		{"device.home", false},
		{"test.arpa", false},
		{"bad..domain", false},
		{".leadingdot.com", false},
		{"trailingdot.com.", false},
		{"has space.com", false},
		{"has*wildcard.com", false},
		{"example.com", true},
		{"api.cloudflare.com", true},
		{"sub.domain.co.uk", true},
		{"MYCLOUD.IO", true},
	}

	for _, tc := range tests {
		got := IsValidPublicDomain(tc.domain)
		if got != tc.expected {
			t.Errorf("IsValidPublicDomain(%q) = %v, expected %v", tc.domain, got, tc.expected)
		}
	}
}

func TestVerifyPublicCACert(t *testing.T) {
	// 1. 空证书测试
	if err := VerifyPublicCACert(nil, nil); err == nil {
		t.Errorf("expected error for nil leaf, got nil")
	}

	// 2. 自签名证书测试 (Issuer == Subject)
	selfSigned := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "localhost"},
		Issuer:    pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	if err := VerifyPublicCACert(selfSigned, nil); err == nil {
		t.Errorf("expected error for self-signed certificate, got nil")
	}

	// 3. 过期证书测试
	expired := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "expired.example.com"},
		Issuer:    pkix.Name{CommonName: "Some CA"},
		NotBefore: time.Now().Add(-48 * time.Hour),
		NotAfter:  time.Now().Add(-24 * time.Hour),
	}
	if err := VerifyPublicCACert(expired, nil); err == nil {
		t.Errorf("expected error for expired certificate, got nil")
	}

	// 4. 尚未生效证书测试
	future := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "future.example.com"},
		Issuer:    pkix.Name{CommonName: "Some CA"},
		NotBefore: time.Now().Add(24 * time.Hour),
		NotAfter:  time.Now().Add(48 * time.Hour),
	}
	if err := VerifyPublicCACert(future, nil); err == nil {
		t.Errorf("expected error for future certificate, got nil")
	}

	// 5. 非受信任根 CA 签发测试
	untrusted := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "untrusted.example.com"},
		Issuer:    pkix.Name{CommonName: "My Private Untrusted CA Root"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	if err := VerifyPublicCACert(untrusted, nil); err == nil {
		t.Errorf("expected error for untrusted CA certificate, got nil")
	}
}



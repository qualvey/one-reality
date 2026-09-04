package scanner

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
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

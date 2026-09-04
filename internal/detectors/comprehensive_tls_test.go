package detectors

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestAnalyzeTLSState_X25519CurveNegotiated(t *testing.T) {
	cts := NewComprehensiveTLSStage()

	cert := &x509.Certificate{
		DNSNames:  []string{"example.com"},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour),
		Subject:   pkix.Name{CommonName: "example.com"},
	}

	state := tls.ConnectionState{
		Version:                     tls.VersionTLS13,
		NegotiatedProtocol:          "h2",
		NegotiatedProtocolIsMutual:  true,
		CurveID:                     tls.X25519,
		CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:            []*x509.Certificate{cert},
		VerifiedChains:              [][]*x509.Certificate{{cert}},
	}

	res := cts.analyzeTLSState(state, "example.com", 50*time.Millisecond)

	if !res.TLS.SupportsTLS13 {
		t.Errorf("expected SupportsTLS13 to be true")
	}
	if !res.TLS.SupportsHTTP2 {
		t.Errorf("expected SupportsHTTP2 to be true")
	}
	if !res.TLS.SupportsX25519 {
		t.Errorf("expected SupportsX25519 to be true without second handshake")
	}
	if !res.SNI.SNIMatch {
		t.Errorf("expected SNIMatch to be true")
	}
}

func TestAnalyzeTLSState_OtherCurve(t *testing.T) {
	cts := NewComprehensiveTLSStage()

	state := tls.ConnectionState{
		Version:                     tls.VersionTLS13,
		NegotiatedProtocol:          "h2",
		NegotiatedProtocolIsMutual:  true,
		CurveID:                     tls.CurveP256,
		CipherSuite:                 tls.TLS_AES_128_GCM_SHA256,
	}

	res := cts.analyzeTLSState(state, "example.com", 50*time.Millisecond)

	if res.TLS.SupportsX25519 {
		t.Errorf("expected SupportsX25519 to be false for CurveP256 before second handshake")
	}
}

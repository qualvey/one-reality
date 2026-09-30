package detectors

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
		Version:                    tls.VersionTLS13,
		NegotiatedProtocol:         "h2",
		NegotiatedProtocolIsMutual: true,
		CurveID:                    tls.X25519,
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:           []*x509.Certificate{cert},
		VerifiedChains:             [][]*x509.Certificate{{cert}},
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
		Version:                    tls.VersionTLS13,
		NegotiatedProtocol:         "h2",
		NegotiatedProtocolIsMutual: true,
		CurveID:                    tls.CurveP256,
		CipherSuite:                tls.TLS_AES_128_GCM_SHA256,
	}

	res := cts.analyzeTLSState(state, "example.com", 50*time.Millisecond)

	if res.TLS.SupportsX25519 {
		t.Errorf("expected SupportsX25519 to be false for CurveP256 before second handshake")
	}
}

func TestVerifyPeerCertificate_ValidChainWithoutVerifiedChains(t *testing.T) {
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RealityChecker Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "*.ryugo.org"},
		DNSNames:     []string{"*.ryugo.org"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	peerIntermediates := []*x509.Certificate{root}
	if err := verifyPeerCertificate(leaf, peerIntermediates, "hk.ryugo.org", now, roots); err != nil {
		t.Fatalf("expected valid wildcard certificate chain to verify: %v", err)
	}
	if err := verifyPeerCertificate(leaf, peerIntermediates, "other.example", now, roots); err == nil {
		t.Fatal("expected certificate hostname mismatch to fail verification")
	}
	if err := verifyPeerCertificate(leaf, peerIntermediates, "hk.ryugo.org", leaf.NotAfter.Add(time.Second), roots); err == nil {
		t.Fatal("expected expired certificate to fail verification")
	}
}

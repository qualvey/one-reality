package detectors

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestCDNDetector_CheckASN(t *testing.T) {
	d := GetCDNDetector()

	// 1. Cloudflare AS13335
	res := d.CheckASN(13335)
	if res == nil || !res.IsCDN || res.CDNProvider != "Cloudflare" {
		t.Errorf("expected Cloudflare CDN for AS13335, got %#v", res)
	}

	// 2. Fastly AS54113
	res = d.CheckASN(54113)
	if res == nil || !res.IsCDN || res.CDNProvider != "Fastly" {
		t.Errorf("expected Fastly CDN for AS54113, got %#v", res)
	}

	// 3. Hetzner AS24940 (独立机房，绝不能是 CDN)
	res = d.CheckASN(24940)
	if res != nil {
		t.Errorf("expected nil for Hetzner AS24940, got %#v", res)
	}
}

func TestCDNDetector_CheckCNAME(t *testing.T) {
	d := GetCDNDetector()

	// 1. CloudFront
	res := d.CheckCNAME("d123456.cloudfront.net")
	if res == nil || !res.IsCDN || res.CDNProvider != "AWS CloudFront" {
		t.Errorf("expected AWS CloudFront for cloudfront.net, got %#v", res)
	}

	// 2. Akamai
	res = d.CheckCNAME("static.example.com.edgekey.net")
	if res == nil || !res.IsCDN || res.CDNProvider != "Akamai" {
		t.Errorf("expected Akamai for edgekey.net, got %#v", res)
	}

	// 3. BunnyCDN
	res = d.CheckCNAME("cdn.test.b-cdn.net")
	if res == nil || !res.IsCDN || res.CDNProvider != "BunnyCDN" {
		t.Errorf("expected BunnyCDN for b-cdn.net, got %#v", res)
	}

	// 4. 普通独立站 CNAME (如 myblog.org -> origin.myblog.org)
	res = d.CheckCNAME("origin.myblog.org")
	if res != nil {
		t.Errorf("expected nil for normal CNAME, got %#v", res)
	}
}

func TestCDNDetector_CheckHTTPHeaders(t *testing.T) {
	d := GetCDNDetector()

	// 1. Cloudflare cf-ray
	res := d.CheckHTTPHeaders(map[string]string{
		"CF-Ray": "87654321-SJC",
		"Server": "cloudflare",
	})
	if res == nil || !res.IsCDN || res.CDNProvider != "Cloudflare" {
		t.Errorf("expected Cloudflare for cf-ray, got %#v", res)
	}

	// 2. AWS CloudFront
	res = d.CheckHTTPHeaders(map[string]string{
		"X-Amz-Cf-Id": "abcde12345==",
	})
	if res == nil || !res.IsCDN || res.CDNProvider != "AWS CloudFront" {
		t.Errorf("expected AWS CloudFront for x-amz-cf-id, got %#v", res)
	}

	// 3. 普通 Nginx / Web 服务器 (非 CDN)
	res = d.CheckHTTPHeaders(map[string]string{
		"Server":       "nginx/1.24.0",
		"Content-Type": "text/html; charset=utf-8",
	})
	if res != nil {
		t.Errorf("expected nil for standard Nginx server, got %#v", res)
	}
}

func TestCDNDetector_CheckCertificate(t *testing.T) {
	d := GetCDNDetector()

	// 1. Cloudflare 专属泛域名证书
	cfCert := &x509.Certificate{
		DNSNames: []string{"example.com", "sni.cloudflaressl.com"},
		Subject:  pkix.Name{CommonName: "sni.cloudflaressl.com"},
		Issuer:   pkix.Name{CommonName: "Cloudflare Inc ECC CA-3"},
	}
	res := d.CheckCertificate(cfCert)
	if res == nil || !res.IsCDN || res.CDNProvider != "Cloudflare" {
		t.Errorf("expected Cloudflare for sni.cloudflaressl.com cert, got %#v", res)
	}

	// 2. 抗误杀验证 1：Google Trust Services 签发的普通独立站证书 (绝不能判定为 CDN)
	gtsCert := &x509.Certificate{
		DNSNames: []string{"myblog.com"},
		Subject:  pkix.Name{CommonName: "myblog.com"},
		Issuer:   pkix.Name{Organization: []string{"Google Trust Services LLC"}, CommonName: "GTS CA 1P5"},
	}
	res = d.CheckCertificate(gtsCert)
	if res != nil {
		t.Errorf("FATAL: Google Trust Services certificate wrongly identified as CDN! %#v", res)
	}

	// 3. 抗误杀验证 2：Amazon ACM 签发的自建 EC2 独立站证书 (绝不能判定为 CDN)
	amzCert := &x509.Certificate{
		DNSNames: []string{"api.customdomain.org"},
		Subject:  pkix.Name{CommonName: "api.customdomain.org"},
		Issuer:   pkix.Name{Organization: []string{"Amazon"}, CommonName: "Amazon RSA 2048 M02"},
	}
	res = d.CheckCertificate(amzCert)
	if res != nil {
		t.Errorf("FATAL: Amazon ACM standalone certificate wrongly identified as CDN! %#v", res)
	}
}

func TestCDNDetector_CheckNS(t *testing.T) {
	d := GetCDNDetector()

	res := d.CheckNS([]string{"ns1.cloudflare.com", "ns2.cloudflare.com"})
	if res == nil || !res.IsCDN || res.CDNProvider != "Cloudflare" {
		t.Errorf("expected Cloudflare for Cloudflare NS, got %#v", res)
	}

	res = d.CheckNS([]string{"dns1.he.net", "dns2.he.net"})
	if res != nil {
		t.Errorf("expected nil for Hurricane Electric NS, got %#v", res)
	}
}

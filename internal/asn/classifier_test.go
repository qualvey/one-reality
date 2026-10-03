package asn

import "testing"

func TestClassifyASN(t *testing.T) {
	tests := []struct {
		asn           int
		name          string
		wantType      string
		wantIsRes     bool
	}{
		// 知名家宽 ASN
		{asn: 4134, name: "China Telecom", wantType: IPTypeResidential, wantIsRes: true},
		{asn: 4837, name: "China Unicom", wantType: IPTypeResidential, wantIsRes: true},
		{asn: 7922, name: "Comcast Cable", wantType: IPTypeResidential, wantIsRes: true},
		{asn: 9381, name: "HKBN", wantType: IPTypeResidential, wantIsRes: true},
		{asn: 3320, name: "Deutsche Telekom", wantType: IPTypeResidential, wantIsRes: true},

		// 关键词匹配家宽
		{asn: 99999, name: "Foobar Home Broadband Network", wantType: IPTypeResidential, wantIsRes: true},

		// 知名机房 / 云厂商
		{asn: 13335, name: "Cloudflare, Inc.", wantType: IPTypeDatacenter, wantIsRes: false},
		{asn: 16509, name: "Amazon.com, Inc. (AWS)", wantType: IPTypeDatacenter, wantIsRes: false},
		{asn: 20473, name: "Choopa, LLC (Vultr)", wantType: IPTypeDatacenter, wantIsRes: false},
		{asn: 24940, name: "Hetzner Online GmbH", wantType: IPTypeDatacenter, wantIsRes: false},
		{asn: 14061, name: "DigitalOcean, LLC", wantType: IPTypeDatacenter, wantIsRes: false},

		// 包含电信词但同时是云厂商 -> 仍判定为机房
		{asn: 88888, name: "Alibaba Cloud Telecom Hosting", wantType: IPTypeDatacenter, wantIsRes: false},
	}

	for _, tt := range tests {
		gotType, gotIsRes, _ := ClassifyASN(tt.asn, tt.name)
		if gotType != tt.wantType || gotIsRes != tt.wantIsRes {
			t.Errorf("ClassifyASN(%d, %q) = (%q, %v), want (%q, %v)",
				tt.asn, tt.name, gotType, gotIsRes, tt.wantType, tt.wantIsRes)
		}
	}
}

func TestIsPureCDNASN(t *testing.T) {
	cdnTests := []struct {
		asn     int
		name    string
		wantCDN bool
	}{
		{asn: 13335, name: "Cloudflare, Inc.", wantCDN: true},
		{asn: 54113, name: "Fastly, Inc.", wantCDN: true},
		{asn: 20940, name: "Akamai", wantCDN: true},
		{asn: 99999, name: "Some Random Cloudflare CDN Node", wantCDN: true},
		{asn: 24940, name: "Hetzner Online GmbH", wantCDN: false},
		{asn: 14061, name: "DigitalOcean, LLC", wantCDN: false},
		{asn: 16276, name: "OVH SAS", wantCDN: false},
	}

	for _, tt := range cdnTests {
		isCDN, name := IsPureCDNASN(tt.asn, tt.name)
		if isCDN != tt.wantCDN {
			t.Errorf("IsPureCDNASN(%d, %q) = (%v, %q), want %v", tt.asn, tt.name, isCDN, name, tt.wantCDN)
		}
	}
}

func TestTransitAndPriorityCalculation(t *testing.T) {
	// 1. IsTransitCountry
	if !IsTransitCountry("US") || !IsTransitCountry("hk") || !IsTransitCountry("JP") || !IsTransitCountry("de") {
		t.Errorf("expected US, HK, JP, DE to be transit countries")
	}
	if IsTransitCountry("FR") || IsTransitCountry("CN") || IsTransitCountry("SG") {
		t.Errorf("FR, CN, SG should not be in the 4 core transit countries")
	}

	// 2. IsTransitDatacenterASN
	// Hetzner (DE, IDC) -> true
	if !IsTransitDatacenterASN(24940, "DE", "Hetzner Online GmbH") {
		t.Errorf("Hetzner should be transit datacenter ASN")
	}
	// AWS (US, IDC) -> true
	if !IsTransitDatacenterASN(16509, "US", "Amazon AWS") {
		t.Errorf("AWS US should be transit datacenter ASN")
	}
	// SAKURA Internet (JP, IDC) -> true
	if !IsTransitDatacenterASN(7684, "JP", "SAKURA Internet Inc.") {
		t.Errorf("Sakura Internet JP should be transit datacenter ASN")
	}
	// Cloudflare (US, CDN) -> false
	if IsTransitDatacenterASN(13335, "US", "Cloudflare, Inc.") {
		t.Errorf("Cloudflare is CDN and should not be transit datacenter ASN")
	}
	// Deutsche Telekom (DE, Residential) -> false
	if IsTransitDatacenterASN(3320, "DE", "Deutsche Telekom") {
		t.Errorf("Deutsche Telekom is residential and should not be transit datacenter ASN")
	}
	// Comcast (US, Residential) -> false
	if IsTransitDatacenterASN(7922, "US", "Comcast Cable") {
		t.Errorf("Comcast is residential and should not be transit datacenter ASN")
	}
	// OVH (FR, IDC) -> false (FR not transit country)
	if IsTransitDatacenterASN(16276, "FR", "OVH SAS") {
		t.Errorf("OVH is in FR, not one of US/HK/JP/DE")
	}

	// 3. CalculateASNPriority
	// CDN -> 0, completed
	prioCDN, statusCDN := CalculateASNPriority(13335, "US", "Cloudflare, Inc.")
	if prioCDN != 0 || statusCDN != "completed" {
		t.Errorf("CDN priority should be 0 completed, got (%d, %s)", prioCDN, statusCDN)
	}

	// Transit Datacenter (US/HK/JP/DE) -> >= 85, pending
	prioTransit, statusTransit := CalculateASNPriority(12345, "US", "Some US Hosting IDC")
	if prioTransit < 85 || statusTransit != "pending" {
		t.Errorf("Transit datacenter priority should be >= 85, got (%d, %s)", prioTransit, statusTransit)
	}

	// Non-transit Datacenter (FR) -> 50 ~ 75, pending
	prioFR, statusFR := CalculateASNPriority(16276, "FR", "OVH SAS", 75)
	if prioFR != 75 || statusFR != "pending" {
		t.Errorf("FR IDC priority should be 75, got (%d, %s)", prioFR, statusFR)
	}

	// Residential -> 10, pending
	prioRes, statusRes := CalculateASNPriority(3320, "DE", "Deutsche Telekom")
	if prioRes != 10 || statusRes != "pending" {
		t.Errorf("Residential priority should be 10, got (%d, %s)", prioRes, statusRes)
	}
}



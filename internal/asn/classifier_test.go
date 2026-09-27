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

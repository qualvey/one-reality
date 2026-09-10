package asn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchPrefixesNormalizesAndDeduplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("resource"); got != "AS15169" {
			t.Fatalf("resource = %q, want AS15169", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"1.1.1.1/24"},{"prefix":"1.1.1.0/24"},{"prefix":"bad"}]}}`))
	}))
	defer server.Close()

	client := NewClient()
	client.endpoint = server.URL
	got, err := client.FetchPrefixes(context.Background(), "15169")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "1.1.1.0/24" {
		t.Fatalf("prefixes = %#v", got)
	}
}

func TestFilterIPVersion(t *testing.T) {
	prefixes := []string{
		"1.1.1.0/24",
		"2001:db8::/32",
		"8.8.8.0/24",
		"2606:4700::/32",
	}

	v4Only := FilterIPVersion(prefixes, true, false)
	if len(v4Only) != 2 || v4Only[0] != "1.1.1.0/24" || v4Only[1] != "8.8.8.0/24" {
		t.Fatalf("v4Only = %#v, want 2 IPv4 prefixes", v4Only)
	}

	v6Only := FilterIPVersion(prefixes, false, true)
	if len(v6Only) != 2 || v6Only[0] != "2001:db8::/32" || v6Only[1] != "2606:4700::/32" {
		t.Fatalf("v6Only = %#v, want 2 IPv6 prefixes", v6Only)
	}

	all := FilterIPVersion(prefixes, false, false)
	if len(all) != 4 {
		t.Fatalf("all = %#v, want 4 prefixes", all)
	}
}


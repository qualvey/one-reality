package detectors

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFollowRedirectsKeepsInitialHTTPSStatus(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() == "https://example.test" {
				return &http.Response{
					StatusCode: http.StatusMovedPermanently,
					Header:     http.Header{"Location": []string{"https://www.example.test/"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	result := (&RedirectStage{}).followRedirects(context.Background(), client, "example.test")

	if !result.Accessible {
		t.Fatal("expected HTTPS endpoint to be accessible")
	}
	if result.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status code = %d, want %d", result.StatusCode, http.StatusMovedPermanently)
	}
	if result.RedirectCount != 1 {
		t.Fatalf("redirect count = %d, want 1", result.RedirectCount)
	}
	if result.URL == "" || result.FinalDomain == "" {
		t.Fatalf("expected final URL and domain, got URL=%q domain=%q", result.URL, result.FinalDomain)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

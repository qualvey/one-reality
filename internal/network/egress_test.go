package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckEgress_CN(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("当前 IP：114.114.114.114  来自于：中国 江苏 南京  chinatelecom.com.cn\n"))
	}))
	defer ts.Close()

	providers := []EgressProvider{
		{
			Name:  "mock-ipip",
			URL:   ts.URL,
			Parse: GetDefaultEgressProviders()[0].Parse,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := CheckEgressWithClient(ctx, ts.Client(), "", providers...)
	if err != nil {
		t.Fatalf("CheckEgressWithClient failed: %v", err)
	}

	if info.IP != "114.114.114.114" {
		t.Errorf("expected IP 114.114.114.114, got %s", info.IP)
	}
	if !info.IsCN {
		t.Errorf("expected IsCN true, got false")
	}
	if info.CountryCode != "CN" {
		t.Errorf("expected CountryCode CN, got %s", info.CountryCode)
	}
}

func TestCheckEgress_NonCN(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success","country":"United States","countryCode":"US","query":"1.1.1.1"}`))
	}))
	defer ts.Close()

	providers := []EgressProvider{
		{
			Name:  "mock-ip-api",
			URL:   ts.URL,
			Parse: GetDefaultEgressProviders()[1].Parse,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := CheckEgressWithClient(ctx, ts.Client(), "", providers...)
	if err != nil {
		t.Fatalf("CheckEgressWithClient failed: %v", err)
	}

	if info.IP != "1.1.1.1" {
		t.Errorf("expected IP 1.1.1.1, got %s", info.IP)
	}
	if info.IsCN {
		t.Errorf("expected IsCN false, got true")
	}
	if info.CountryCode != "US" {
		t.Errorf("expected CountryCode US, got %s", info.CountryCode)
	}
}

func TestCheckEgress_Fallback(t *testing.T) {
	// 第一个服务报错 500
	ts1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer ts1.Close()

	// 第二个服务正常返回
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ip":"8.8.8.8","country":"United States","country_code":"US"}`))
	}))
	defer ts2.Close()

	providers := []EgressProvider{
		{
			Name:  "mock-fail",
			URL:   ts1.URL,
			Parse: GetDefaultEgressProviders()[0].Parse,
		},
		{
			Name:  "mock-success",
			URL:   ts2.URL,
			Parse: GetDefaultEgressProviders()[2].Parse,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	info, err := CheckEgressWithClient(ctx, ts2.Client(), "", providers...)
	if err != nil {
		t.Fatalf("expected fallback success, got err: %v", err)
	}

	if info.Source != "mock-success" {
		t.Errorf("expected source mock-success, got %s", info.Source)
	}
	if info.IP != "8.8.8.8" {
		t.Errorf("expected IP 8.8.8.8, got %s", info.IP)
	}
	if info.IsCN {
		t.Errorf("expected IsCN false, got true")
	}
}

func TestCheckEgress_AllFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer ts.Close()

	providers := []EgressProvider{
		{
			Name:  "mock-fail",
			URL:   ts.URL,
			Parse: GetDefaultEgressProviders()[0].Parse,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := CheckEgressWithClient(ctx, ts.Client(), "", providers...)
	if err == nil {
		t.Fatalf("expected error when all providers fail, got nil")
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"

	"RealityChecker/internal/types"
)

func TestShouldExcludeDomain_ConfigDriven(t *testing.T) {
	filter := types.RealityFilterConfig{
		ExcludeDomains:  []string{"private.example.com", "localhost"},
		ExcludeSuffixes: []string{".internal", ".local", ".arpa"},
		ExcludePatterns: []string{"kubernetes", "fake certificate"},
	}

	tests := []struct {
		domain string
		want   bool
	}{
		{"private.example.com", true},
		{"localhost", true},
		{"demo.internal", true},
		{"node.local", true},
		{"1.0.0.127.in-addr.arpa", true},
		{"kubernetes-ingress.example.com", true},
		{"some-fake certificate-domain.com", true},
		{"*.wildcard.com", true},
		{"192.168.1.1", true},
		{"good.example.com", false},
		{"apple.com", false},
		{"microsoft.com", false},
	}

	for _, tt := range tests {
		got := ShouldExcludeDomain(tt.domain, filter)
		if got != tt.want {
			t.Errorf("ShouldExcludeDomain(%q) = %v, want %v", tt.domain, got, tt.want)
		}
	}
}

func TestLoadExcludeRulesFromFile(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "rules.txt")

	content := `# Test rules
include_suffixes:
  .com
  .org

exclude_suffixes:
  .custom
  .testlab

exclude_domains:
  test.domain.com

exclude_patterns:
  mock-k8s

exclude_status:
  302
  404
`
	if err := os.WriteFile(rulesFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test rules file: %v", err)
	}

	domains, suffixes, patterns, statusCodes, includeSuffixes, err := LoadExcludeRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("LoadExcludeRulesFromFile failed: %v", err)
	}

	if len(domains) != 1 || domains[0] != "test.domain.com" {
		t.Errorf("unexpected domains: %v", domains)
	}
	if len(suffixes) != 2 || suffixes[0] != ".custom" || suffixes[1] != ".testlab" {
		t.Errorf("unexpected suffixes: %v", suffixes)
	}
	if len(patterns) != 1 || patterns[0] != "mock-k8s" {
		t.Errorf("unexpected patterns: %v", patterns)
	}
	if len(statusCodes) != 2 || statusCodes[0] != 302 || statusCodes[1] != 404 {
		t.Errorf("unexpected statusCodes: %v", statusCodes)
	}
	if len(includeSuffixes) != 2 || includeSuffixes[0] != ".com" || includeSuffixes[1] != ".org" {
		t.Errorf("unexpected includeSuffixes: %v", includeSuffixes)
	}
}

func TestShouldExcludeStatusCode(t *testing.T) {
	filter := types.RealityFilterConfig{
		ExcludeStatus: []int{301, 302, 404, 500},
	}

	if !ShouldExcludeStatusCode(302, filter) {
		t.Errorf("expected 302 to be excluded")
	}
	if !ShouldExcludeStatusCode(404, filter) {
		t.Errorf("expected 404 to be excluded")
	}
	if ShouldExcludeStatusCode(200, filter) {
		t.Errorf("expected 200 to NOT be excluded")
	}
}

func TestProxyConfig_LoadAndMerge(t *testing.T) {
	tempDir := t.TempDir()

	// 1. 测试对象模式
	yamlContent1 := `
proxy:
  url: "http://127.0.0.1:7890"
  download: true
  scanner: true
`
	file1 := filepath.Join(tempDir, "config1.yaml")
	if err := os.WriteFile(file1, []byte(yamlContent1), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg1, err := LoadConfig(file1)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg1.Proxy.URL != "http://127.0.0.1:7890" {
		t.Errorf("expected url http://127.0.0.1:7890, got %s", cfg1.Proxy.URL)
	}
	if !cfg1.Proxy.Download {
		t.Errorf("expected download true")
	}
	if !cfg1.Proxy.Scanner {
		t.Errorf("expected scanner true")
	}

	// 2. 测试标量字符串简写模式
	yamlContent2 := `
proxy: "socks5://127.0.0.1:1080"
`
	file2 := filepath.Join(tempDir, "config2.yaml")
	if err := os.WriteFile(file2, []byte(yamlContent2), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg2, err := LoadConfig(file2)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg2.Proxy.URL != "socks5://127.0.0.1:1080" {
		t.Errorf("expected url socks5://127.0.0.1:1080, got %s", cfg2.Proxy.URL)
	}
	if !cfg2.Proxy.Download {
		t.Errorf("expected download default true")
	}
	if cfg2.Proxy.Scanner {
		t.Errorf("expected scanner default false")
	}

	// 3. 测试 network.proxy 兼容模式
	yamlContent3 := `
network:
  proxy: "http://10.0.0.1:8080"
`
	file3 := filepath.Join(tempDir, "config3.yaml")
	if err := os.WriteFile(file3, []byte(yamlContent3), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg3, err := LoadConfig(file3)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg3.Proxy.URL != "http://10.0.0.1:8080" {
		t.Errorf("expected url http://10.0.0.1:8080, got %s", cfg3.Proxy.URL)
	}
}

func TestDatabaseConfig_LoadAndMerge(t *testing.T) {
	tempDir := t.TempDir()

	// 1. 默认配置测试
	defaultCfg := GetDefaultConfig()
	if defaultCfg.Database.Driver != "sqlite" {
		t.Errorf("expected default driver sqlite, got %s", defaultCfg.Database.Driver)
	}
	if defaultCfg.Database.SQLite.Path != "data/reality_targets.db" {
		t.Errorf("expected default sqlite path data/reality_targets.db, got %s", defaultCfg.Database.SQLite.Path)
	}

	// 2. 从 YAML 文件加载 postgres 配置测试
	yamlContent := `
database:
  driver: "postgres"
  postgres:
    host: "10.0.0.5"
    port: 5433
    user: "reality_user"
    password: "secret_password"
    dbname: "reality_prod"
    sslmode: "require"
    max_conns: 100
`
	configFile := filepath.Join(tempDir, "config_db.yaml")
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write config_db.yaml: %v", err)
	}

	cfg, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Database.Driver != "postgres" {
		t.Errorf("expected driver postgres, got %s", cfg.Database.Driver)
	}
	if cfg.Database.Postgres.Host != "10.0.0.5" {
		t.Errorf("expected host 10.0.0.5, got %s", cfg.Database.Postgres.Host)
	}
	if cfg.Database.Postgres.Port != 5433 {
		t.Errorf("expected port 5433, got %d", cfg.Database.Postgres.Port)
	}
	if cfg.Database.Postgres.User != "reality_user" {
		t.Errorf("expected user reality_user, got %s", cfg.Database.Postgres.User)
	}
	if cfg.Database.Postgres.Password != "secret_password" {
		t.Errorf("expected password secret_password, got %s", cfg.Database.Postgres.Password)
	}
	if cfg.Database.Postgres.DBName != "reality_prod" {
		t.Errorf("expected dbname reality_prod, got %s", cfg.Database.Postgres.DBName)
	}
	if cfg.Database.Postgres.SSLMode != "require" {
		t.Errorf("expected sslmode require, got %s", cfg.Database.Postgres.SSLMode)
	}
	if cfg.Database.Postgres.MaxConns != 100 {
		t.Errorf("expected max_conns 100, got %d", cfg.Database.Postgres.MaxConns)
	}
	if cfg.LoadedConfigFile != configFile {
		t.Errorf("expected LoadedConfigFile %s, got %s", configFile, cfg.LoadedConfigFile)
	}
}

func TestLoadConfig_EnvAndLoadedPath(t *testing.T) {
	tempDir := t.TempDir()
	envConfigFile := filepath.Join(tempDir, "custom_env_config.yml")
	yamlContent := `
database:
  driver: "postgres"
  postgres:
    host: "192.168.1.100"
    port: 5432
    user: "rchecker"
    password: "passwd"
    dbname: "reality"
`
	if err := os.WriteFile(envConfigFile, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	t.Setenv("REALITY_CONFIG", envConfigFile)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig from env failed: %v", err)
	}
	if cfg.LoadedConfigFile != envConfigFile {
		t.Errorf("expected LoadedConfigFile %s, got %s", envConfigFile, cfg.LoadedConfigFile)
	}
	if cfg.Database.Postgres.User != "rchecker" {
		t.Errorf("expected user rchecker, got %s", cfg.Database.Postgres.User)
	}
	if cfg.Database.Postgres.DBName != "reality" {
		t.Errorf("expected dbname reality, got %s", cfg.Database.Postgres.DBName)
	}
}




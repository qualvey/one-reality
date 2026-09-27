package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"RealityChecker/internal/types"

	"gopkg.in/yaml.v3"
)

// LoadConfig 加载配置
func LoadConfig(configPath string) (*types.Config, error) {
	// 获取默认配置
	config := getDefaultConfig()

	// 1. 如果显式提供了配置文件路径，优先尝试加载
	if configPath != "" {
		if err := loadConfigFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("加载配置文件失败: %v", err)
		}
		config.LoadedConfigFile = configPath
		validateAndSetDefaults(config)
		return config, nil
	}

	// 2. 检查环境变量 REALITY_CONFIG
	if envPath := os.Getenv("REALITY_CONFIG"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			if err := loadConfigFromFile(config, envPath); err == nil {
				config.LoadedConfigFile = envPath
				validateAndSetDefaults(config)
				return config, nil
			}
		}
	}

	// 3. 收集候选查找目录 (当前工作目录以及可执行文件所在目录)
	var candidateDirs []string
	candidateDirs = append(candidateDirs, ".")

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		if exeDir != "." && exeDir != "" {
			alreadyExists := false
			for _, d := range candidateDirs {
				if d == exeDir {
					alreadyExists = true
					break
				}
			}
			if !alreadyExists {
				candidateDirs = append(candidateDirs, exeDir)
			}
		}
	}

	// 依次探测配置文件 (config.yaml, config.yml)
	fileNames := []string{"config.yaml", "config.yml"}
	for _, dir := range candidateDirs {
		for _, name := range fileNames {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				if err := loadConfigFromFile(config, p); err != nil {
					return nil, fmt.Errorf("检测到配置文件 %s，但解析失败: %w", p, err)
				}
				config.LoadedConfigFile = p
				validateAndSetDefaults(config)
				return config, nil
			}
		}
	}

	// 验证并设置默认值（未找到配置文件，使用默认配置）
	validateAndSetDefaults(config)
	return config, nil
}

// loadConfigFromFile 从文件加载配置
func loadConfigFromFile(config *types.Config, filePath string) error {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("配置文件不存在: %s", filePath)
	}

	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML
	var fileConfig types.Config
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 合并配置（文件配置覆盖默认配置）
	mergeConfig(config, &fileConfig)

	return nil
}

// mergeConfig 合并配置
func mergeConfig(defaultConfig *types.Config, fileConfig *types.Config) {
	// 代理配置
	if fileConfig.Proxy.URL != "" {
		defaultConfig.Proxy = fileConfig.Proxy
	} else if fileConfig.Network.Proxy != "" {
		defaultConfig.Proxy.URL = fileConfig.Network.Proxy
		defaultConfig.Proxy.Download = true
		defaultConfig.Proxy.Scanner = false
	}

	// 网络配置
	if fileConfig.Network.Timeout > 0 {
		defaultConfig.Network.Timeout = fileConfig.Network.Timeout
	}
	if fileConfig.Network.Retries >= 0 {
		defaultConfig.Network.Retries = fileConfig.Network.Retries
	}
	if len(fileConfig.Network.DNSServers) > 0 {
		defaultConfig.Network.DNSServers = fileConfig.Network.DNSServers
	}
	if fileConfig.Network.Proxy != "" {
		defaultConfig.Network.Proxy = fileConfig.Network.Proxy
	}

	// TLS配置
	if fileConfig.TLS.MinVersion > 0 {
		defaultConfig.TLS.MinVersion = fileConfig.TLS.MinVersion
	}
	if fileConfig.TLS.MaxVersion > 0 {
		defaultConfig.TLS.MaxVersion = fileConfig.TLS.MaxVersion
	}

	// 并发配置
	if fileConfig.Concurrency.MaxConcurrent > 0 {
		defaultConfig.Concurrency.MaxConcurrent = fileConfig.Concurrency.MaxConcurrent
	}
	if fileConfig.Concurrency.CheckTimeout > 0 {
		defaultConfig.Concurrency.CheckTimeout = fileConfig.Concurrency.CheckTimeout
	}
	if fileConfig.Concurrency.CacheTTL > 0 {
		defaultConfig.Concurrency.CacheTTL = fileConfig.Concurrency.CacheTTL
	}

	// 输出配置
	if fileConfig.Output.Format != "" {
		defaultConfig.Output.Format = fileConfig.Output.Format
	}
	defaultConfig.Output.Color = fileConfig.Output.Color
	defaultConfig.Output.Verbose = fileConfig.Output.Verbose

	// 缓存配置
	defaultConfig.Cache.DNSEnabled = fileConfig.Cache.DNSEnabled
	defaultConfig.Cache.ResultEnabled = fileConfig.Cache.ResultEnabled
	if fileConfig.Cache.TTL > 0 {
		defaultConfig.Cache.TTL = fileConfig.Cache.TTL
	}
	if fileConfig.Cache.MaxSize > 0 {
		defaultConfig.Cache.MaxSize = fileConfig.Cache.MaxSize
	}

	// 批量配置
	defaultConfig.Batch.StreamOutput = fileConfig.Batch.StreamOutput
	defaultConfig.Batch.ProgressBar = fileConfig.Batch.ProgressBar
	if fileConfig.Batch.ReportFormat != "" {
		defaultConfig.Batch.ReportFormat = fileConfig.Batch.ReportFormat
	}
	if fileConfig.Batch.Timeout > 0 {
		defaultConfig.Batch.Timeout = fileConfig.Batch.Timeout
	}

	// REALITY 选型策略配置
	defaultConfig.RealityFilter.RequireNoCN = fileConfig.RealityFilter.RequireNoCN
	defaultConfig.RealityFilter.CheckGFW = fileConfig.RealityFilter.CheckGFW
	defaultConfig.RealityFilter.IPv4Only = fileConfig.RealityFilter.IPv4Only
	defaultConfig.RealityFilter.IPv6Only = fileConfig.RealityFilter.IPv6Only
	defaultConfig.RealityFilter.UseCache = fileConfig.RealityFilter.UseCache
	defaultConfig.RealityFilter.VerifyCache = fileConfig.RealityFilter.VerifyCache
	defaultConfig.RealityFilter.NoResume = fileConfig.RealityFilter.NoResume
	if fileConfig.RealityFilter.CacheMaxDays > 0 {
		defaultConfig.RealityFilter.CacheMaxDays = fileConfig.RealityFilter.CacheMaxDays
	}
	if fileConfig.RealityFilter.ScanThreads > 0 {
		defaultConfig.RealityFilter.ScanThreads = fileConfig.RealityFilter.ScanThreads
	}
	if fileConfig.RealityFilter.ScanTimeout > 0 {
		defaultConfig.RealityFilter.ScanTimeout = fileConfig.RealityFilter.ScanTimeout
	}
	defaultConfig.RealityFilter.RequireNoCDN = fileConfig.RealityFilter.RequireNoCDN
	defaultConfig.RealityFilter.RequireNoHot = fileConfig.RealityFilter.RequireNoHot
	defaultConfig.RealityFilter.RequireNoDefaultPage = fileConfig.RealityFilter.RequireNoDefaultPage
	if fileConfig.RealityFilter.ExcludeRulesFile != "" {
		defaultConfig.RealityFilter.ExcludeRulesFile = fileConfig.RealityFilter.ExcludeRulesFile
	}
	if fileConfig.RealityFilter.MaxHandshakeMS > 0 {
		defaultConfig.RealityFilter.MaxHandshakeMS = fileConfig.RealityFilter.MaxHandshakeMS
	}
	if fileConfig.RealityFilter.MinCertDays > 0 {
		defaultConfig.RealityFilter.MinCertDays = fileConfig.RealityFilter.MinCertDays
	}
	if fileConfig.RealityFilter.MinStars > 0 {
		defaultConfig.RealityFilter.MinStars = fileConfig.RealityFilter.MinStars
	}
	if len(fileConfig.RealityFilter.IncludeSuffixes) > 0 {
		defaultConfig.RealityFilter.IncludeSuffixes = mergeUniqueStrings(defaultConfig.RealityFilter.IncludeSuffixes, fileConfig.RealityFilter.IncludeSuffixes)
	}
	if len(fileConfig.RealityFilter.ExcludeDomains) > 0 {
		defaultConfig.RealityFilter.ExcludeDomains = mergeUniqueStrings(defaultConfig.RealityFilter.ExcludeDomains, fileConfig.RealityFilter.ExcludeDomains)
	}
	if len(fileConfig.RealityFilter.ExcludeSuffixes) > 0 {
		defaultConfig.RealityFilter.ExcludeSuffixes = mergeUniqueStrings(defaultConfig.RealityFilter.ExcludeSuffixes, fileConfig.RealityFilter.ExcludeSuffixes)
	}
	if len(fileConfig.RealityFilter.ExcludePatterns) > 0 {
		defaultConfig.RealityFilter.ExcludePatterns = mergeUniqueStrings(defaultConfig.RealityFilter.ExcludePatterns, fileConfig.RealityFilter.ExcludePatterns)
	}
	if len(fileConfig.RealityFilter.ExcludeStatus) > 0 {
		defaultConfig.RealityFilter.ExcludeStatus = mergeUniqueInts(defaultConfig.RealityFilter.ExcludeStatus, fileConfig.RealityFilter.ExcludeStatus)
	}

	// 日志配置
	if fileConfig.Log.Level != "" {
		defaultConfig.Log.Level = fileConfig.Log.Level
	}
	if fileConfig.Log.File != "" {
		defaultConfig.Log.File = fileConfig.Log.File
	}

	// 数据库配置
	if fileConfig.Database.Driver != "" {
		defaultConfig.Database.Driver = fileConfig.Database.Driver
	}
	if fileConfig.Database.SQLite.Path != "" {
		defaultConfig.Database.SQLite.Path = fileConfig.Database.SQLite.Path
	}
	if fileConfig.Database.SQLite.BusyTimeout > 0 {
		defaultConfig.Database.SQLite.BusyTimeout = fileConfig.Database.SQLite.BusyTimeout
	}
	if fileConfig.Database.SQLite.JournalMode != "" {
		defaultConfig.Database.SQLite.JournalMode = fileConfig.Database.SQLite.JournalMode
	}
	if fileConfig.Database.SQLite.Synchronous != "" {
		defaultConfig.Database.SQLite.Synchronous = fileConfig.Database.SQLite.Synchronous
	}
	if fileConfig.Database.Postgres.DSN != "" {
		defaultConfig.Database.Postgres.DSN = fileConfig.Database.Postgres.DSN
	}
	if fileConfig.Database.Postgres.Host != "" {
		defaultConfig.Database.Postgres.Host = fileConfig.Database.Postgres.Host
	}
	if fileConfig.Database.Postgres.Port > 0 {
		defaultConfig.Database.Postgres.Port = fileConfig.Database.Postgres.Port
	}
	if fileConfig.Database.Postgres.User != "" {
		defaultConfig.Database.Postgres.User = fileConfig.Database.Postgres.User
	}
	if fileConfig.Database.Postgres.Password != "" {
		defaultConfig.Database.Postgres.Password = fileConfig.Database.Postgres.Password
	}
	if fileConfig.Database.Postgres.DBName != "" {
		defaultConfig.Database.Postgres.DBName = fileConfig.Database.Postgres.DBName
	}
	if fileConfig.Database.Postgres.SSLMode != "" {
		defaultConfig.Database.Postgres.SSLMode = fileConfig.Database.Postgres.SSLMode
	}
	if fileConfig.Database.Postgres.MaxConns > 0 {
		defaultConfig.Database.Postgres.MaxConns = fileConfig.Database.Postgres.MaxConns
	}
	if fileConfig.Database.Postgres.MinConns > 0 {
		defaultConfig.Database.Postgres.MinConns = fileConfig.Database.Postgres.MinConns
	}
	if fileConfig.Database.Postgres.MaxConnLifetime > 0 {
		defaultConfig.Database.Postgres.MaxConnLifetime = fileConfig.Database.Postgres.MaxConnLifetime
	}
	if fileConfig.Database.Postgres.MaxConnIdleTime > 0 {
		defaultConfig.Database.Postgres.MaxConnIdleTime = fileConfig.Database.Postgres.MaxConnIdleTime
	}
}

// GetDefaultConfig 获取全局标准默认配置
func GetDefaultConfig() *types.Config {
	return getDefaultConfig()
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *types.Config {
	return &types.Config{
		Proxy: types.ProxyConfig{
			URL:      "",
			Download: true,
			Scanner:  false,
		},
		Network: types.NetworkConfig{
			Timeout:    3 * time.Second, // 减少到3秒
			Retries:    1,
			DNSServers: []string{"223.5.5.5", "114.114.114.114"},
		},
		TLS: types.TLSConfig{
			MinVersion: 771, // TLS 1.2
			MaxVersion: 772, // TLS 1.3
		},
		Concurrency: types.ConcurrencyConfig{
			MaxConcurrent: 8,
			CheckTimeout:  3 * time.Second, // 减少到3秒
			CacheTTL:      5 * time.Minute,
		},
		Output: types.OutputConfig{
			Color:   true,
			Verbose: false,
			Format:  "table",
		},
		Cache: types.CacheConfig{
			DNSEnabled:    true,
			ResultEnabled: true,
			TTL:           5 * time.Minute,
			MaxSize:       1000,
		},
		Batch: types.BatchConfig{
			StreamOutput: false,
			ProgressBar:  true,
			ReportFormat: "text",
			Timeout:      30 * time.Second,
		},
		RealityFilter: types.RealityFilterConfig{
			RequireNoCN:          true,
			CheckGFW:             false,
			UseCache:             true,
			CacheMaxDays:         7,
			ScanThreads:          200,
			ScanTimeout:          3,
			RequireNoCDN:         true,
			MaxHandshakeMS:       800,
			RequireNoHot:         true,
			MinCertDays:          7,
			MinStars:             3,
			RequireNoDefaultPage: true,
			ExcludeRulesFile:     "data/exclude_rules.txt",
			IncludeSuffixes:      []string{},
			ExcludeDomains: []string{
				"localhost",
				"server.domain.com",
				"johnnasmalley.hostname",
				"Kubernetes Ingress Controller Fake Certificate",
				"CloudFlare Origin Certificate",
				"FortiGate",
				"Unspecified",
			},
			ExcludeSuffixes: []string{
				".local",
				".internal",
				".lan",
				".home",
				".corp",
				".arpa",
				".test",
				".example",
				".invalid",
				".localhost",
				".onion",
			},
			ExcludePatterns: []string{
				"kubernetes",
				"ingress controller fake certificate",
				"fake certificate",
			},
			ExcludeStatus: []int{
				400, 401, 403, 404, 407, 408, 429,
				500, 501, 502, 503, 504,
			},
		},
		Log: types.LogConfig{
			Level: "info",
			File:  "",
		},
		Database: types.DatabaseConfig{
			Driver: "sqlite",
			SQLite: types.SQLiteConfig{
				Path:        "data/reality_targets.db",
				BusyTimeout: 5000,
				JournalMode: "WAL",
				Synchronous: "NORMAL",
			},
			Postgres: types.PostgresConfig{
				Host:            "127.0.0.1",
				Port:            5432,
				User:            "postgres",
				Password:        "",
				DBName:          "reality_checker",
				SSLMode:         "disable",
				MaxConns:        50,
				MinConns:        5,
				MaxConnLifetime: time.Hour,
				MaxConnIdleTime: 30 * time.Minute,
			},
		},
	}
}

// validateAndSetDefaults 验证配置并设置默认值
func validateAndSetDefaults(config *types.Config) {
	// 数据库配置校验与缺省补充
	if config.Database.Driver == "" {
		config.Database.Driver = "sqlite"
	}
	config.Database.Driver = strings.ToLower(strings.TrimSpace(config.Database.Driver))
	if config.Database.SQLite.Path == "" {
		config.Database.SQLite.Path = "data/reality_targets.db"
	}
	if config.Database.SQLite.BusyTimeout <= 0 {
		config.Database.SQLite.BusyTimeout = 5000
	}
	if config.Database.SQLite.JournalMode == "" {
		config.Database.SQLite.JournalMode = "WAL"
	}
	if config.Database.SQLite.Synchronous == "" {
		config.Database.SQLite.Synchronous = "NORMAL"
	}
	if config.Database.Postgres.Port <= 0 {
		config.Database.Postgres.Port = 5432
	}
	if config.Database.Postgres.SSLMode == "" {
		config.Database.Postgres.SSLMode = "disable"
	}
	if config.Database.Postgres.MaxConns <= 0 {
		config.Database.Postgres.MaxConns = 50
	}
	if config.Database.Postgres.MinConns <= 0 {
		config.Database.Postgres.MinConns = 5
	}
	if config.Database.Postgres.MaxConnLifetime <= 0 {
		config.Database.Postgres.MaxConnLifetime = time.Hour
	}
	if config.Database.Postgres.MaxConnIdleTime <= 0 {
		config.Database.Postgres.MaxConnIdleTime = 30 * time.Minute
	}
	// 网络配置验证
	if config.Network.Timeout <= 0 {
		config.Network.Timeout = 30 * time.Second
	}
	if config.Network.Retries < 0 {
		config.Network.Retries = 3
	}
	if len(config.Network.DNSServers) == 0 {
		config.Network.DNSServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	// TLS配置验证
	if config.TLS.MinVersion == 0 {
		config.TLS.MinVersion = 771 // TLS 1.2
	}
	if config.TLS.MaxVersion == 0 {
		config.TLS.MaxVersion = 772 // TLS 1.3
	}

	// 并发配置验证
	if config.Concurrency.MaxConcurrent <= 0 {
		config.Concurrency.MaxConcurrent = 8
	}
	if config.Concurrency.CheckTimeout <= 0 {
		config.Concurrency.CheckTimeout = 30 * time.Second
	}
	if config.Concurrency.CacheTTL <= 0 {
		config.Concurrency.CacheTTL = 5 * time.Minute
	}

	// 输出配置验证
	if config.Output.Format == "" {
		config.Output.Format = "table"
	}

	// 缓存配置验证
	if config.Cache.TTL <= 0 {
		config.Cache.TTL = 5 * time.Minute
	}
	if config.Cache.MaxSize <= 0 {
		config.Cache.MaxSize = 1000
	}

	// 批量配置验证
	if config.Batch.ReportFormat == "" {
		config.Batch.ReportFormat = "text"
	}
	if config.Batch.Timeout <= 0 {
		config.Batch.Timeout = 60 * time.Second
	}

	// 尝试加载外部排除规则文件
	rulesPath := config.RealityFilter.ExcludeRulesFile
	if rulesPath == "" {
		rulesPath = "data/exclude_rules.txt"
	}
	if _, err := os.Stat(rulesPath); err == nil {
		domains, suffixes, patterns, statusCodes, incSuffixes, err := LoadExcludeRulesFromFile(rulesPath)
		if err == nil {
			config.RealityFilter.IncludeSuffixes = mergeUniqueStrings(config.RealityFilter.IncludeSuffixes, incSuffixes)
			config.RealityFilter.ExcludeDomains = mergeUniqueStrings(config.RealityFilter.ExcludeDomains, domains)
			config.RealityFilter.ExcludeSuffixes = mergeUniqueStrings(config.RealityFilter.ExcludeSuffixes, suffixes)
			config.RealityFilter.ExcludePatterns = mergeUniqueStrings(config.RealityFilter.ExcludePatterns, patterns)
			config.RealityFilter.ExcludeStatus = mergeUniqueInts(config.RealityFilter.ExcludeStatus, statusCodes)
		}
	}
}

// LoadExcludeRulesFromFile 从外部规则文件加载排除规则
func LoadExcludeRulesFromFile(filePath string) (domains, suffixes, patterns []string, statusCodes []int, includeSuffixes []string, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 检查节标题
		if strings.HasSuffix(line, ":") {
			currentSection = strings.ToLower(line)
			continue
		}

		switch currentSection {
		case "include_suffixes:":
			includeSuffixes = append(includeSuffixes, line)
		case "exclude_domains:":
			domains = append(domains, line)
		case "exclude_suffixes:":
			suffixes = append(suffixes, line)
		case "exclude_patterns:":
			patterns = append(patterns, line)
		case "exclude_status:", "exclude_status_codes:":
			if code, err := strconv.Atoi(line); err == nil {
				statusCodes = append(statusCodes, code)
			}
		default:
			// 默认处理为 pattern
			patterns = append(patterns, line)
		}
	}

	return domains, suffixes, patterns, statusCodes, includeSuffixes, scanner.Err()
}

// ShouldExcludeDomain 根据 REALITY 策略与排除规则判断是否应该排除指定域名
func ShouldExcludeDomain(domain string, filter types.RealityFilterConfig) bool {
	if domain == "" {
		return true
	}

	// 排除通配符域名
	if strings.Contains(domain, "*") {
		return true
	}

	domainTrimmed := strings.TrimSpace(domain)
	domainLower := strings.ToLower(domainTrimmed)

	// 排除直接 IP 地址 (IPv4 / IPv6)
	if net.ParseIP(domainTrimmed) != nil {
		return true
	}

	// 排除过短或连续点的无效域名
	if len(domainLower) < 3 || strings.Contains(domainLower, "..") {
		return true
	}

	// 如果配置了白名单后缀 (IncludeSuffixes)，必须命中其中之一
	if len(filter.IncludeSuffixes) > 0 {
		matchedInclude := false
		for _, suffix := range filter.IncludeSuffixes {
			s := strings.ToLower(strings.TrimSpace(suffix))
			if s != "" {
				if !strings.HasPrefix(s, ".") {
					s = "." + s
				}
				if strings.HasSuffix(domainLower, s) {
					matchedInclude = true
					break
				}
			}
		}
		if !matchedInclude {
			return true
		}
	}

	// 1. 排除指定域名（精确或包含）
	for _, pattern := range filter.ExcludeDomains {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p != "" && (domainLower == p || strings.Contains(domainLower, p)) {
			return true
		}
	}

	// 2. 排除指定后缀（如 .local, .internal, .arpa）
	for _, suffix := range filter.ExcludeSuffixes {
		s := strings.ToLower(strings.TrimSpace(suffix))
		if s != "" {
			if !strings.HasPrefix(s, ".") {
				s = "." + s
			}
			if strings.HasSuffix(domainLower, s) {
				return true
			}
		}
	}

	// 3. 排除特定特征模式
	for _, pattern := range filter.ExcludePatterns {
		p := strings.ToLower(strings.TrimSpace(pattern))
		if p != "" && strings.Contains(domainLower, p) {
			return true
		}
	}

	return false
}

// mergeUniqueStrings 合并两个字符串切片并去重
func mergeUniqueStrings(base, additions []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range base {
		cleaned := strings.TrimSpace(item)
		if cleaned != "" && !seen[cleaned] {
			seen[cleaned] = true
			result = append(result, cleaned)
		}
	}

	for _, item := range additions {
		cleaned := strings.TrimSpace(item)
		if cleaned != "" && !seen[cleaned] {
			seen[cleaned] = true
			result = append(result, cleaned)
		}
	}

	return result
}

// mergeUniqueInts 合并两个整型切片并去重
func mergeUniqueInts(base, additions []int) []int {
	seen := make(map[int]bool)
	var result []int

	for _, item := range base {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	for _, item := range additions {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ShouldExcludeStatusCode 判断状态码是否属于排除列表
func ShouldExcludeStatusCode(statusCode int, filter types.RealityFilterConfig) bool {
	if len(filter.ExcludeStatus) > 0 {
		for _, s := range filter.ExcludeStatus {
			if s == statusCode {
				return true
			}
		}
		return false
	}
	return types.IsStatusCodeExcluded(statusCode)
}



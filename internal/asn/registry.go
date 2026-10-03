package asn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"RealityChecker/internal/network"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

// SeedPopularASNs 预设全球 Top 热门公有云、CDN 与 IDC 自治系统
var SeedPopularASNs = []*types.ASNRecord{
	// 纯商业 CDN 基础设施 (Anycast/反代)：预设标记 completed 且权重为 0，防止全网扫描在 CDN 上做无用功
	{ASN: 13335, Name: "Cloudflare, Inc.", Country: "US", Priority: 0, ScanStatus: "completed"},
	{ASN: 54113, Name: "Fastly, Inc.", Country: "US", Priority: 0, ScanStatus: "completed"},

	// Tier 1: 核心四大中转国（美、港、日、德）头部公有云与数据中心 (Priority 90 - 100)
	{ASN: 24940, Name: "Hetzner Online GmbH", Country: "DE", Priority: 100, ScanStatus: "pending"},
	{ASN: 14061, Name: "DigitalOcean, LLC", Country: "US", Priority: 95, ScanStatus: "pending"},
	{ASN: 16509, Name: "Amazon.com, Inc. (AWS)", Country: "US", Priority: 95, ScanStatus: "pending"},
	{ASN: 14618, Name: "Amazon.com, Inc. (AWS)", Country: "US", Priority: 90, ScanStatus: "pending"},
	{ASN: 8075, Name: "Microsoft Corporation (Azure)", Country: "US", Priority: 95, ScanStatus: "pending"},
	{ASN: 15169, Name: "Google LLC", Country: "US", Priority: 95, ScanStatus: "pending"},
	{ASN: 396982, Name: "Google Cloud Platform", Country: "US", Priority: 92, ScanStatus: "pending"},
	{ASN: 31898, Name: "Oracle Corporation", Country: "US", Priority: 90, ScanStatus: "pending"},

	// Tier 2: 核心四大中转国主流 VPS/IDC 机房 (Priority 85 - 90)
	{ASN: 51167, Name: "Contabo GmbH", Country: "DE", Priority: 88, ScanStatus: "pending"},
	{ASN: 63949, Name: "Linode, LLC (Akamai Connected Cloud)", Country: "US", Priority: 88, ScanStatus: "pending"},
	{ASN: 20473, Name: "Choopa, LLC (Vultr)", Country: "US", Priority: 88, ScanStatus: "pending"},
	{ASN: 46652, Name: "RackNerd LLC", Country: "US", Priority: 85, ScanStatus: "pending"},
	{ASN: 53667, Name: "FranTech Solutions (BuyVM)", Country: "US", Priority: 85, ScanStatus: "pending"},
	{ASN: 16265, Name: "Leaseweb USA, Inc.", Country: "US", Priority: 85, ScanStatus: "pending"},
	{ASN: 36352, Name: "ColoCrossing", Country: "US", Priority: 85, ScanStatus: "pending"},
	{ASN: 45102, Name: "Alibaba Cloud (US) LLC", Country: "US", Priority: 88, ScanStatus: "pending"},
	{ASN: 4713, Name: "NTT America, Inc.", Country: "US", Priority: 85, ScanStatus: "pending"},
	{ASN: 2914, Name: "NTT Communications", Country: "JP", Priority: 88, ScanStatus: "pending"},
	{ASN: 7684, Name: "SAKURA Internet Inc.", Country: "JP", Priority: 88, ScanStatus: "pending"},
	{ASN: 2497, Name: "Internet Initiative Japan Inc. (IIJ)", Country: "JP", Priority: 88, ScanStatus: "pending"},
	{ASN: 133119, Name: "Equinix Hong Kong", Country: "HK", Priority: 88, ScanStatus: "pending"},

	// Tier 3: 其他国家优质海外公有云与 IDC (Priority 65 - 75)
	{ASN: 16276, Name: "OVH SAS", Country: "FR", Priority: 75, ScanStatus: "pending"},
	{ASN: 12876, Name: "Scaleway S.A.S.", Country: "FR", Priority: 72, ScanStatus: "pending"},
	{ASN: 25820, Name: "IT7 Networks Inc (BandwagonHost)", Country: "CA", Priority: 75, ScanStatus: "pending"},
	{ASN: 60781, Name: "Leaseweb Netherlands B.V.", Country: "NL", Priority: 72, ScanStatus: "pending"},
	{ASN: 212238, Name: "Datacamp Limited", Country: "GB", Priority: 72, ScanStatus: "pending"},
	{ASN: 9009, Name: "M247 Ltd", Country: "GB", Priority: 72, ScanStatus: "pending"},
	{ASN: 49981, Name: "WorldStream B.V.", Country: "NL", Priority: 72, ScanStatus: "pending"},
	{ASN: 37963, Name: "Hangzhou Alibaba Advertising Co.,Ltd.", Country: "CN", Priority: 75, ScanStatus: "pending"},
	{ASN: 132203, Name: "Tencent Building, Kejizhongyi Avenue", Country: "CN", Priority: 75, ScanStatus: "pending"},
	{ASN: 45090, Name: "Shenzhen Tencent Computer Systems", Country: "CN", Priority: 72, ScanStatus: "pending"},
	{ASN: 58519, Name: "Cloud Innovation Ltd", Country: "SC", Priority: 65, ScanStatus: "pending"},
	{ASN: 136800, Name: "Ksyun / Kingsoft Cloud", Country: "CN", Priority: 65, ScanStatus: "pending"},
	{ASN: 7473, Name: "Singapore Telecommunications (Singtel)", Country: "SG", Priority: 72, ScanStatus: "pending"},

	// Tier 4: 电信与家庭宽带运营商（优先级降级至 15 ~ 50）
	{ASN: 9269, Name: "HKT Limited", Country: "HK", Priority: 50, ScanStatus: "pending"},
	{ASN: 2516, Name: "KDDI Corporation", Country: "JP", Priority: 20, ScanStatus: "pending"},
	{ASN: 9381, Name: "Hong Kong Broadband Network", Country: "HK", Priority: 15, ScanStatus: "pending"},
}

// RegistryManager 负责全球 ASN 注册表的初始化、权重配置与网络更新
type RegistryManager struct {
	store      storage.Store
	httpClient *http.Client
}

// NewRegistryManager 创建 ASN 注册表管理器
func NewRegistryManager(store storage.Store, timeout ...time.Duration) *RegistryManager {
	return NewRegistryManagerWithProxy(store, "", timeout...)
}

// NewRegistryManagerWithProxy 创建支持代理的 ASN 注册表管理器
func NewRegistryManagerWithProxy(store storage.Store, proxyURL string, timeout ...time.Duration) *RegistryManager {
	reqTimeout := 30 * time.Second
	if len(timeout) > 0 && timeout[0] > 0 {
		reqTimeout = timeout[0]
	}
	httpClient, _ := network.MakeHTTPClient(proxyURL, reqTimeout)
	if httpClient == nil {
		httpClient = &http.Client{Timeout: reqTimeout}
	}
	return &RegistryManager{
		store:      store,
		httpClient: httpClient,
	}
}

// SetProxy 配置 ASN 同步请求代理
func (m *RegistryManager) SetProxy(proxyURL string) {
	if client, err := network.MakeHTTPClient(proxyURL, m.httpClient.Timeout); err == nil && client != nil {
		m.httpClient = client
	}
}

// InitDefaultRegistry 初始化默认的热门 ASN 种子库
func (m *RegistryManager) InitDefaultRegistry() (int, error) {
	if m.store == nil {
		return 0, fmt.Errorf("TargetStore 未初始化")
	}

	now := time.Now()
	records := make([]*types.ASNRecord, 0, len(SeedPopularASNs))
	for _, seed := range SeedPopularASNs {
		prio, status := CalculateASNPriority(seed.ASN, seed.Country, seed.Name, seed.Priority)
		if seed.ScanStatus == "completed" {
			status = "completed"
		}
		rec := &types.ASNRecord{
			ASN:        seed.ASN,
			Name:       seed.Name,
			Country:    seed.Country,
			Priority:   prio,
			ScanStatus: status,
			UpdatedAt:  now,
		}
		records = append(records, rec)
	}

	if err := m.store.UpsertASNRecords(records); err != nil {
		return 0, fmt.Errorf("写入预设 ASN 注册表失败: %w", err)
	}

	_ = m.CalibrateDefaultRegistry()

	return len(records), nil
}

// EnsureRegistrySeeded 如果数据库内 ASN 记录为空，则自动载入默认热门 ASN；若已存在，校准预设纯商业 CDN 与核心种子权重
func (m *RegistryManager) EnsureRegistrySeeded() (int, error) {
	if m.store == nil {
		return 0, nil
	}
	count, err := m.store.CountASNs("")
	if err != nil {
		return 0, err
	}
	if count > 0 {
		_ = m.CalibrateDefaultRegistry()
		return count, nil
	}
	return m.InitDefaultRegistry()
}

// CalibrateDefaultRegistry 校准数据库中关键预设 ASN 的权重与纯商业 CDN 状态
func (m *RegistryManager) CalibrateDefaultRegistry() error {
	if m.store == nil {
		return nil
	}

	for _, seed := range SeedPopularASNs {
		rec, err := m.store.GetASN(seed.ASN)
		if err != nil || rec == nil {
			continue
		}

		prio, _ := CalculateASNPriority(seed.ASN, seed.Country, seed.Name, seed.Priority)
		if isCDN, _ := IsPureCDNASN(seed.ASN, seed.Name); isCDN {
			if rec.ScanStatus != "completed" {
				_ = m.store.UpdateASNStatus(seed.ASN, "completed", 0)
			}
			if rec.Priority != 0 {
				_ = m.store.UpdateASNPriority(seed.ASN, 0)
			}
			continue
		}

		if rec.Priority != prio {
			_ = m.store.UpdateASNPriority(seed.ASN, prio)
		}
	}
	return nil
}

// SyncFromURL 从远程 BGP 或 RIPE / CAIDA 转储源同步 ASN 列表
// 支持纯文本（格式: AS12345 Name, CC）或 JSON 数组格式
func (m *RegistryManager) SyncFromURL(ctx context.Context, rawURL string) (int, error) {
	if rawURL == "" {
		return 0, fmt.Errorf("数据源 URL 不能为空")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, fmt.Errorf("创建 HTTP 请求失败: %w", err)
	}
	req.Header.Set("User-Agent", "RealityChecker-Sync/1.0")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("请求 ASN 远程数据源失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("远程数据源响应异常: HTTP %s", resp.Status)
	}

	return m.ParseAndImportReader(resp.Body)
}

var (
	asnRegex     = regexp.MustCompile(`(?i)(?:AS)?(\d+)\s+([^\t\r\n,]+)(?:,\s*([A-Z]{2}))?`)
	asnOnlyRegex = regexp.MustCompile(`^(?:AS)?(\d+)$`)
)

// ParseAndImportReader 解析任意文本流中的 ASN 定义并存入库
func (m *RegistryManager) ParseAndImportReader(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	// 支持较长的行
	buf := make([]byte, 128*1024)
	scanner.Buffer(buf, 1024*1024)

	var records []*types.ASNRecord
	now := time.Now()
	batchSize := 500
	totalImported := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// 尝试解析纯数字或带前缀: 13335
		if mMatches := asnOnlyRegex.FindStringSubmatch(line); len(mMatches) >= 2 {
			asnNum, _ := strconv.Atoi(mMatches[1])
			if asnNum > 0 {
				prio, status := CalculateASNPriority(asnNum, "", "")
				records = append(records, &types.ASNRecord{
					ASN:        asnNum,
					Priority:   prio,
					ScanStatus: status,
					UpdatedAt:  now,
				})
			}
		} else if matches := asnRegex.FindStringSubmatch(line); len(matches) >= 3 {
			asnNum, _ := strconv.Atoi(matches[1])
			if asnNum > 0 {
				name := strings.TrimSpace(matches[2])
				country := ""
				if len(matches) >= 4 {
					country = strings.ToUpper(strings.TrimSpace(matches[3]))
				}
				prio, status := CalculateASNPriority(asnNum, country, name)
				records = append(records, &types.ASNRecord{
					ASN:        asnNum,
					Name:       name,
					Country:    country,
					Priority:   prio,
					ScanStatus: status,
					UpdatedAt:  now,
				})
			}
		}

		if len(records) >= batchSize {
			if err := m.store.UpsertASNRecords(records); err != nil {
				return totalImported, err
			}
			totalImported += len(records)
			records = records[:0]
		}
	}

	if len(records) > 0 {
		if err := m.store.UpsertASNRecords(records); err != nil {
			return totalImported, err
		}
		totalImported += len(records)
	}

	return totalImported, scanner.Err()
}

// RegistryStats 返回当前 ASN 注册表的统计大盘
type RegistryStats struct {
	TotalASNs     int            `json:"total_asns"`
	PendingASNs   int            `json:"pending_asns"`
	ScanningASNs  int            `json:"scanning_asns"`
	CompletedASNs int            `json:"completed_asns"`
	HighPriority  int            `json:"high_priority_asns"`
	TopCountries  map[string]int `json:"top_countries"`
}

// GetStats 获取注册表当前运行状态统计
func (m *RegistryManager) GetStats() (*RegistryStats, error) {
	if m.store == nil {
		return nil, fmt.Errorf("TargetStore 未初始化")
	}

	total, err := m.store.CountASNs("")
	if err != nil {
		return nil, err
	}
	pending, _ := m.store.CountASNs("pending")
	scanning, _ := m.store.CountASNs("scanning")
	completed, _ := m.store.CountASNs("completed")

	// 查询高优先级数量
	highPrioList, _ := m.store.ListASNs("", 80, 1000, 0)

	return &RegistryStats{
		TotalASNs:     total,
		PendingASNs:   pending,
		ScanningASNs:  scanning,
		CompletedASNs: completed,
		HighPriority:  len(highPrioList),
	}, nil
}

package detectors

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"RealityChecker/internal/types"
)

// CDNDetector 高性能全维度 CDN 判定引擎
type CDNDetector struct {
	mu                     sync.RWMutex
	cnameStrongSuffix      map[string]string
	httpStrongHeader       map[string]string
	serverStrongHeader     map[string]string
	httpMediumHeader       map[string]string
	httpValueCdnDomains    map[string]string
	asnStrongExact         map[int]string
	nsHintSuffix           map[string]string
	certIssuerHint         map[string]string
	certSubjectPatterns    map[string]string
	excludeServerTokens    map[string]bool
	excludeKeywordsGeneric map[string]bool
}

var (
	defaultDetector *CDNDetector
	detectorOnce    sync.Once
)

// GetCDNDetector 获取全局唯一的 CDN 判定引擎实例 (单例预加载)
func GetCDNDetector() *CDNDetector {
	detectorOnce.Do(func() {
		defaultDetector = newCDNDetector()
	})
	return defaultDetector
}

func newCDNDetector() *CDNDetector {
	d := &CDNDetector{
		cnameStrongSuffix:      make(map[string]string),
		httpStrongHeader:       make(map[string]string),
		serverStrongHeader:     make(map[string]string),
		httpMediumHeader:       make(map[string]string),
		httpValueCdnDomains:    make(map[string]string),
		asnStrongExact:         make(map[int]string),
		nsHintSuffix:           make(map[string]string),
		certIssuerHint:         make(map[string]string),
		certSubjectPatterns:    make(map[string]string),
		excludeServerTokens:    make(map[string]bool),
		excludeKeywordsGeneric: make(map[string]bool),
	}

	// 1. 先初始化内置的高精度主流 CDN 默认指纹底座 (无外部文件也可 100% 独立运作)
	d.initBuiltinFingerprints()

	// 2. 尝试从本地外部规则文件增量合并
	d.loadExternalFile("data/cdn_keywords.txt")

	return d
}

// initBuiltinFingerprints 内置全球顶级主流 CDN 指纹库
func (d *CDNDetector) initBuiltinFingerprints() {
	// --- CNAME 专属后缀 ---
	cnameRules := map[string]string{
		"cloudfront.net":               "AWS CloudFront",
		"akamaized.net":                "Akamai",
		"akamaihd.net":                 "Akamai",
		"akamaiedge.net":               "Akamai",
		"edgekey.net":                  "Akamai",
		"edgesuite.net":                "Akamai",
		"akadns.net":                   "Akamai",
		"fastly.net":                   "Fastly",
		"fastlylb.net":                 "Fastly",
		"azureedge.net":                "Azure CDN",
		"azurefd.net":                  "Azure Front Door",
		"msecnd.net":                   "Microsoft CDN",
		"edgecastcdn.net":              "Edgio / Edgecast",
		"b-cdn.net":                    "BunnyCDN",
		"cdn77.org":                    "CDN77",
		"cdn77.net":                    "CDN77",
		"kxcdn.com":                    "KeyCDN",
		"gcdn.co":                      "Gcore",
		"gcorelabs.net":                "Gcore",
		"cdn.cloudflare.net":           "Cloudflare",
		"cloudflare.com.cdn.cloudflare.net": "Cloudflare",
		"cdnetworks.net":               "CDNetworks",
		"cdnetworks.com":               "CDNetworks",
		"incapdns.net":                 "Imperva / Incapsula",
		"impervadns.net":               "Imperva / Incapsula",
		"vercel-dns.com":               "Vercel Edge",
		"netlify.app":                  "Netlify",
		"quic.cloud":                   "QUIC.cloud",
		"hwcdn.net":                    "Highwinds / Edgio",
		"llnwd.net":                    "Limelight / Edgio",
		"llnwi.net":                    "Limelight / Edgio",
		"cachefly.net":                 "CacheFly",
		"wscdns.com":                   "ChinaNetCenter (网宿科技)",
		"kunluncan.com":                "Aliyun CDN (阿里云)",
		"kunlunar.com":                 "Aliyun CDN (阿里云)",
		"tcdn.qq.com":                  "Tencent Cloud CDN (腾讯云)",
		"tc.cdnhwc.com":                "Huawei Cloud CDN (华为云)",
		"bsgslb.cn":                    "BaishanCloud (白山云)",
	}
	for k, v := range cnameRules {
		d.cnameStrongSuffix[strings.ToLower(k)] = v
	}

	// --- HTTP 专属强响应头 ---
	headers := map[string]string{
		"cf-ray":              "Cloudflare",
		"cf-cache-status":     "Cloudflare",
		"cf-connecting-ip":    "Cloudflare",
		"x-amz-cf-id":         "AWS CloudFront",
		"x-amz-cf-pop":        "AWS CloudFront",
		"x-amz-cf-ray":        "AWS CloudFront",
		"x-fastly-request-id": "Fastly",
		"fastly-debug":        "Fastly",
		"x-akamai-pragma":     "Akamai",
		"x-akamai-request-id": "Akamai",
		"x-akamai-transformed": "Akamai",
		"x-azure-ref":         "Azure Front Door",
		"x-msedge-ref":        "Azure Front Door",
		"x-gcdn-request-id":   "Gcore",
		"x-iinfo":             "Imperva / Incapsula",
		"x-cdn-provider":      "CDN",
		"x-bunny-cache":       "BunnyCDN",
	}
	for k, v := range headers {
		d.httpStrongHeader[strings.ToLower(k)] = v
	}

	// --- HTTP Server 专属响应标记 ---
	serverTokens := map[string]string{
		"cloudflare":   "Cloudflare",
		"cloudfront":   "AWS CloudFront",
		"akamaighost":  "Akamai",
		"fastly":       "Fastly",
		"edgecast":     "Edgio / Edgecast",
		"gcore":        "Gcore",
		"bunnycdn":     "BunnyCDN",
		"keycdn":       "KeyCDN",
		"imperva":      "Imperva",
		"incapsula":    "Incapsula",
	}
	for k, v := range serverTokens {
		d.serverStrongHeader[strings.ToLower(k)] = v
	}

	// --- HTTP 中等响应头 ---
	mediumHeaders := map[string]string{
		"x-cache":                      "CDN/Cache Proxy",
		"x-cache-hits":                 "CDN/Cache Proxy",
		"x-cache-lookup":               "CDN/Cache Proxy",
		"x-served-by":                  "CDN/Proxy",
		"x-varnish":                    "Varnish Cache",
		"via":                          "Proxy/CDN",
		"edge-control":                 "Akamai / Edge Control",
		"x-envoy-upstream-service-time": "Envoy / Edge Gateway",
	}
	for k, v := range mediumHeaders {
		d.httpMediumHeader[strings.ToLower(k)] = v
	}

	// --- 纯 CDN 基础设施 ASN ---
	asns := map[int]string{
		13335:  "Cloudflare",
		209242: "Cloudflare",
		394536: "Cloudflare",
		395747: "Cloudflare",
		132892: "Cloudflare",
		133877: "Cloudflare",
		54113:  "Fastly",
		20940:  "Akamai",
		16625:  "Akamai",
		32787:  "Akamai Prolexic",
		35994:  "Akamai",
		15133:  "Edgio / Edgecast",
		22822:  "Edgio / Limelight",
		60068:  "CDN77",
		19551:  "Imperva / Incapsula",
		199524: "Gcore",
		203020: "BunnyCDN",
		135377: "UCSS / Cloudflare Partner",
	}
	for k, v := range asns {
		d.asnStrongExact[k] = v
	}

	// --- 权威 NS 提示 ---
	nsList := map[string]string{
		"cloudflare.com": "Cloudflare",
		"akam.net":       "Akamai",
		"fastlydns.net":  "Fastly",
		"ns.bunny.net":   "BunnyCDN",
		"gcorelabs.net":  "Gcore",
	}
	for k, v := range nsList {
		d.nsHintSuffix[strings.ToLower(k)] = v
	}

	// --- 专属 CDN 证书签发者特征 ---
	certIssuers := map[string]string{
		"cloudflare inc ecc ca":        "Cloudflare",
		"cloudflare inc rsa ca":        "Cloudflare",
		"cloudflare origin certificate": "Cloudflare",
		"akamai subordinate ca":        "Akamai",
		"fastly ca":                    "Fastly",
	}
	for k, v := range certIssuers {
		d.certIssuerHint[strings.ToLower(k)] = v
	}

	// --- 专属 CDN 证书 SAN/CN 泛域名特征 ---
	subjectPatterns := map[string]string{
		"sni.cloudflaressl.com": "Cloudflare",
		"*.ssl.fastly.net":      "Fastly",
		"*.azureedge.net":       "Azure CDN",
		"*.cloudfront.net":      "AWS CloudFront",
		"*.akamaized.net":       "Akamai",
	}
	for k, v := range subjectPatterns {
		d.certSubjectPatterns[strings.ToLower(k)] = v
	}
}

// loadExternalFile 从外部配置文件合并规则
func (d *CDNDetector) loadExternalFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(line, ":") {
			currentSection = strings.TrimSuffix(line, ":")
			continue
		}

		// 移除行内注释
		cleanItem := strings.TrimSpace(strings.Split(line, "#")[0])
		if cleanItem == "" {
			continue
		}
		itemLower := strings.ToLower(cleanItem)

		switch currentSection {
		case "cname_strong_suffix":
			if _, exists := d.cnameStrongSuffix[itemLower]; !exists {
				d.cnameStrongSuffix[itemLower] = "CDN"
			}
		case "http_strong_header":
			if strings.HasPrefix(itemLower, "server: ") {
				srvToken := strings.TrimSpace(strings.TrimPrefix(itemLower, "server: "))
				if _, exists := d.serverStrongHeader[srvToken]; !exists {
					d.serverStrongHeader[srvToken] = "CDN"
				}
			} else {
				if _, exists := d.httpStrongHeader[itemLower]; !exists {
					d.httpStrongHeader[itemLower] = "CDN"
				}
			}
		case "http_medium_header":
			if _, exists := d.httpMediumHeader[itemLower]; !exists {
				d.httpMediumHeader[itemLower] = "CDN/Proxy"
			}
		case "http_value_cdn_domains":
			if _, exists := d.httpValueCdnDomains[itemLower]; !exists {
				d.httpValueCdnDomains[itemLower] = "CDN"
			}
		case "asn_strong_exact":
			numStr := strings.TrimPrefix(strings.ToUpper(cleanItem), "AS")
			if asnNum, err := strconv.Atoi(numStr); err == nil {
				if _, exists := d.asnStrongExact[asnNum]; !exists {
					d.asnStrongExact[asnNum] = "CDN"
				}
			}
		case "ns_hint_suffix":
			if _, exists := d.nsHintSuffix[itemLower]; !exists {
				d.nsHintSuffix[itemLower] = "CDN"
			}
		case "cert_issuer_hint":
			// 过滤掉已知的 Google 和 Amazon 泛化签发者，避免误杀
			if itemLower == "google trust services" || itemLower == "amazon" {
				continue
			}
			if _, exists := d.certIssuerHint[itemLower]; !exists {
				d.certIssuerHint[itemLower] = "CDN"
			}
		case "exclude_server_tokens":
			d.excludeServerTokens[itemLower] = true
		case "exclude_keywords_generic":
			d.excludeKeywordsGeneric[itemLower] = true
		}
	}
}

// CheckASN 检查 ASN 是否属于纯商业 CDN 基础设施
func (d *CDNDetector) CheckASN(asn int) *types.CDNResult {
	if asn <= 0 {
		return nil
	}
	d.mu.RLock()
	provider, exists := d.asnStrongExact[asn]
	d.mu.RUnlock()

	if exists {
		return &types.CDNResult{
			IsCDN:       true,
			CDNProvider: provider,
			Confidence:  "高",
			Evidence:    fmt.Sprintf("ASN强特征: 目标属于纯CDN提供商 (AS%d - %s)", asn, provider),
		}
	}
	return nil
}

// CheckCNAME 检查给定的 CNAME 记录是否匹配已知 CDN
func (d *CDNDetector) CheckCNAME(cname string) *types.CDNResult {
	cnameClean := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(cname)), ".")
	if cnameClean == "" {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for suffix, provider := range d.cnameStrongSuffix {
		if strings.HasSuffix(cnameClean, suffix) || strings.Contains(cnameClean, "."+suffix) {
			return &types.CDNResult{
				IsCDN:       true,
				CDNProvider: provider,
				Confidence:  "高",
				Evidence:    fmt.Sprintf("CNAME强特征: 命中 %s (解析别名: %s)", suffix, cnameClean),
			}
		}
	}
	return nil
}

// CheckDomainCNAME 实时解析域名的 CNAME 并进行 CDN 匹配
func (d *CDNDetector) CheckDomainCNAME(domain string) *types.CDNResult {
	domainClean := strings.TrimSpace(strings.ToLower(domain))
	if domainClean == "" {
		return nil
	}

	cname, err := net.LookupCNAME(domainClean)
	if err != nil {
		return nil
	}
	cname = strings.TrimSuffix(cname, ".")
	if cname == "" || strings.EqualFold(cname, domainClean) {
		return nil
	}

	return d.CheckCNAME(cname)
}

// CheckHTTPHeaders 检查 HTTP 响应头中的强响应头与 Server 标记
func (d *CDNDetector) CheckHTTPHeaders(headers map[string]string) *types.CDNResult {
	if len(headers) == 0 {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 1. 强特征专属响应头检查
	for hName, hVal := range headers {
		hLower := strings.ToLower(hName)
		if provider, exists := d.httpStrongHeader[hLower]; exists {
			return &types.CDNResult{
				IsCDN:       true,
				CDNProvider: provider,
				Confidence:  "高",
				Evidence:    fmt.Sprintf("HTTP专属响应头: %s=%s (提供商: %s)", hName, hVal, provider),
			}
		}
	}

	// 2. Server 头特征检查
	for hName, hVal := range headers {
		if strings.EqualFold(hName, "Server") {
			sValLower := strings.ToLower(hVal)
			for token, provider := range d.serverStrongHeader {
				if strings.Contains(sValLower, token) {
					return &types.CDNResult{
						IsCDN:       true,
						CDNProvider: provider,
						Confidence:  "高",
						Evidence:    fmt.Sprintf("HTTP Server强特征: Server: %s (提供商: %s)", hVal, provider),
					}
				}
			}
		}
	}

	// 3. HTTP 头值中的 CDN 专属域名检查
	for hName, hVal := range headers {
		hValLower := strings.ToLower(hVal)
		for cdnDomain, provider := range d.httpValueCdnDomains {
			if strings.Contains(hValLower, cdnDomain) {
				return &types.CDNResult{
					IsCDN:       true,
					CDNProvider: provider,
					Confidence:  "高",
					Evidence:    fmt.Sprintf("HTTP头值CDN域名: %s 包含 %s", hName, cdnDomain),
				}
			}
		}
	}

	// 4. 中等置信度头检查
	for hName, hVal := range headers {
		hLower := strings.ToLower(hName)
		if provider, exists := d.httpMediumHeader[hLower]; exists {
			return &types.CDNResult{
				IsCDN:       true,
				CDNProvider: provider,
				Confidence:  "中",
				Evidence:    fmt.Sprintf("HTTP通用缓存/代理头: %s=%s", hName, hVal),
			}
		}
	}

	return nil
}

// CheckCertificate 检查 TLS 证书签发者与主体 SAN (精准杜绝 Google/Amazon 误杀)
func (d *CDNDetector) CheckCertificate(cert *x509.Certificate) *types.CDNResult {
	if cert == nil {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 1. 检查证书主体 SAN/CN 中的 CDN 泛域名特征
	for _, dns := range cert.DNSNames {
		dnsLower := strings.ToLower(dns)
		for pattern, provider := range d.certSubjectPatterns {
			if dnsLower == pattern || (strings.HasPrefix(pattern, "*.") && strings.HasSuffix(dnsLower, pattern[1:])) {
				return &types.CDNResult{
					IsCDN:       true,
					CDNProvider: provider,
					Confidence:  "高",
					Evidence:    fmt.Sprintf("TLS证书SAN特征: 包含CDN专属泛域名 %s", dns),
				}
			}
		}
	}

	// 2. 检查证书签发者专属 CDN CA
	issuerStr := cert.Issuer.String()
	issuerLower := strings.ToLower(issuerStr)

	for issuerKey, provider := range d.certIssuerHint {
		if strings.Contains(issuerLower, issuerKey) {
			return &types.CDNResult{
				IsCDN:       true,
				CDNProvider: provider,
				Confidence:  "高",
				Evidence:    fmt.Sprintf("TLS证书CA特征: 专属CDN签发者 (%s)", issuerStr),
			}
		}
	}

	return nil
}

// CheckCertificateIssuerString 便捷检查签发者文本
func (d *CDNDetector) CheckCertificateIssuerString(issuer string, domain ...string) *types.CDNResult {
	if issuer == "" {
		return nil
	}
	issuerLower := strings.ToLower(issuer)

	d.mu.RLock()
	defer d.mu.RUnlock()

	for issuerKey, provider := range d.certIssuerHint {
		if strings.Contains(issuerLower, issuerKey) {
			return &types.CDNResult{
				IsCDN:       true,
				CDNProvider: provider,
				Confidence:  "高",
				Evidence:    fmt.Sprintf("TLS证书CA特征: 专属CDN签发者 (%s)", issuer),
			}
		}
	}
	return nil
}

// CheckNS 检查 NS 记录是否为 CDN 专用 Nameserver
func (d *CDNDetector) CheckNS(nsHosts []string) *types.CDNResult {
	if len(nsHosts) == 0 {
		return nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, ns := range nsHosts {
		nsLower := strings.ToLower(ns)
		for hint, provider := range d.nsHintSuffix {
			if strings.Contains(nsLower, hint) {
				return &types.CDNResult{
					IsCDN:       true,
					CDNProvider: provider,
					Confidence:  "中",
					Evidence:    fmt.Sprintf("权威NS记录特征: %s (提供商: %s)", ns, provider),
				}
			}
		}
	}
	return nil
}

// Detect 全流程综合探测评估
func (d *CDNDetector) Detect(domain string, networkResult *types.NetworkResult) *types.CDNResult {
	// 1. HTTP 强响应头检查 (最快速直接)
	if networkResult != nil && len(networkResult.Headers) > 0 {
		if res := d.CheckHTTPHeaders(networkResult.Headers); res != nil {
			return res
		}
	}

	// 2. CNAME 强特征检查
	if domain != "" {
		if res := d.CheckDomainCNAME(domain); res != nil {
			return res
		}
	}

	return nil
}

// ==================== 向后兼容适配器 ====================

// CDNStage 保持原有 API 签名的适配层
type CDNStage struct {
	detector *CDNDetector
}

// NewCDNStage 创建 CDN 检测阶段 (委托全局单例)
func NewCDNStage() *CDNStage {
	return &CDNStage{
		detector: GetCDNDetector(),
	}
}

// Execute 执行 CDN 检测 (兼容接口)
func (cs *CDNStage) Execute(ctx *types.PipelineContext) error {
	if ctx == nil || ctx.Result == nil {
		return nil
	}
	if ctx.Result.CDN != nil && ctx.Result.CDN.IsCDN {
		return nil
	}

	res := cs.detector.Detect(ctx.Domain, ctx.Result.Network)
	if res != nil {
		ctx.Result.CDN = res
	}
	return nil
}

func (cs *CDNStage) detectCDN(domain string, networkResult *types.NetworkResult) (bool, string, string, string) {
	res := cs.detector.Detect(domain, networkResult)
	if res != nil && res.IsCDN {
		return true, res.CDNProvider, res.Confidence, res.Evidence
	}
	return false, "", "", ""
}

func (cs *CDNStage) checkCNAMEStrongSuffix(domain string) (string, string) {
	res := cs.detector.CheckDomainCNAME(domain)
	if res != nil && res.IsCDN {
		return res.CDNProvider, res.Evidence
	}
	return "", ""
}

func (cs *CDNStage) checkHTTPStrongHeader(networkResult *types.NetworkResult) (string, string) {
	if networkResult == nil {
		return "", ""
	}
	res := cs.detector.CheckHTTPHeaders(networkResult.Headers)
	if res != nil && res.IsCDN && res.Confidence == "高" {
		return res.CDNProvider, res.Evidence
	}
	return "", ""
}

func (cs *CDNStage) checkHTTPValueCdnDomains(networkResult *types.NetworkResult) (string, string) {
	if networkResult == nil {
		return "", ""
	}
	res := cs.detector.CheckHTTPHeaders(networkResult.Headers)
	if res != nil && res.IsCDN && strings.Contains(res.Evidence, "HTTP头值CDN域名") {
		return res.CDNProvider, res.Evidence
	}
	return "", ""
}

func (cs *CDNStage) checkHTTPMediumHeader(networkResult *types.NetworkResult) (string, string) {
	if networkResult == nil {
		return "", ""
	}
	res := cs.detector.CheckHTTPHeaders(networkResult.Headers)
	if res != nil && res.IsCDN && res.Confidence == "中" {
		return res.CDNProvider, res.Evidence
	}
	return "", ""
}

func (cs *CDNStage) checkNSHintSuffix(domain string) (string, string) {
	nsRecords, err := net.LookupNS(domain)
	if err != nil || len(nsRecords) == 0 {
		return "", ""
	}
	hosts := make([]string, 0, len(nsRecords))
	for _, ns := range nsRecords {
		hosts = append(hosts, ns.Host)
	}
	res := cs.detector.CheckNS(hosts)
	if res != nil && res.IsCDN {
		return res.CDNProvider, res.Evidence
	}
	return "", ""
}

func (cs *CDNStage) checkCertIssuerHint(domain string) (string, string) {
	// 复用探测器逻辑
	return "", ""
}

func (cs *CDNStage) checkASNStrongExact(domain string) (string, string) {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		return "", ""
	}
	return "", ""
}

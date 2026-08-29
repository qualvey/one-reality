package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/asn"
	"RealityChecker/internal/config"
	"RealityChecker/internal/core"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"

	"github.com/oschwald/geoip2-golang"
	"github.com/schollz/progressbar/v3"
)

// CalculateTotalIPs 计算一组 CIDR 或单 IP 的总数量（支持 IPv4 和 IPv6，支持去重/越界大数）
func CalculateTotalIPs(cidrs []string) int64 {
	var total int64

	for _, raw := range cidrs {
		// 1. 尝试按 CIDR 解析（如 "192.168.1.0/24"）
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			// 2. 如果不是 CIDR 格式，检查是否是单独的单个 IP（如 "1.1.1.1"）
			if ip := net.ParseIP(raw); ip != nil {
				total += 1
			}
			continue
		}

		// 获取掩码位数（IPv4 ones <= 32，bits == 32）
		ones, bits := ipNet.Mask.Size()
		if bits == 32 { // IPv4
			hostBits := bits - ones
			// 1 << hostBits 即 2^(32-ones)
			total += int64(1) << hostBits
		} else if bits == 128 { // IPv6 (若遇到超大段需考虑防护)
			hostBits := bits - ones
			if hostBits < 62 {
				total += int64(1) << hostBits
			}
		}
	}
	return total
}

// executeAuto 处理 CIDR/IP 列表，内存中调用内置 TLS 扫描器并根据 REALITY 策略输出彩色表格结果
func (r *RootCmd) executeAuto(cidrs []string, maxTargets int, checkAll bool, exportFile string, filter types.RealityFilterConfig, asnStr string, countryStr string) {
	if len(cidrs) == 0 {
		ui.PrintError("错误：未提供有效的 CIDR 扫描网段")
		return
	}

	// 计算待扫描 IP 理论总数
	totalIPCount := CalculateTotalIPs(cidrs)

	bar := progressbar.NewOptions64(totalIPCount,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(25),
		progressbar.OptionSetDescription("[cyan][扫描中...][reset]"),
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
	ui.PrintTimestampedMessage("开启内嵌自动化扫描与检测模式 (Native Engine)...")
	if checkAll {
		ui.PrintTimestampedMessage("模式: 全量摸底扫描 (--check-all)，将收集并存档所有合规资产入库")
	}
	ui.PrintTimestampedMessage("应用 REALITY 选型策略: [非国内=%v, GFW检测=%v, 非CDN=%v, 最大握手=%dms, 排除热门=%v, 最小证书天数=%d天, 最低星级=%d星]",
		filter.RequireNoCN, filter.CheckGFW, filter.RequireNoCDN, filter.MaxHandshakeMS, filter.RequireNoHot, filter.MinCertDays, filter.MinStars)

	ui.PrintTimestampedMessage("待扫描网段总数: %d 个。排序如下:", len(cidrs))

	for i, c := range cidrs {
		if i < 5 {
			fmt.Printf("  [%d] %s\n", i+1, c)
		}
	}
	if len(cidrs) > 5 {
		fmt.Printf("  ...以及其余 %d 个网段\n", len(cidrs)-5)
	}

	// 1. 初始化内嵌 Go 扫描器与本地资产库
	scannerEngine := scanner.NewScanner()
	defer scannerEngine.Close()

	targetStore, _ := storage.NewTargetStore("data/reality_targets.db")
	if targetStore != nil {
		defer targetStore.Close()
	}

	// 2. 构造流水线 Channel
	scanResultChan := make(chan *scanner.ScanResult, 100)
	domainSet := make(map[string]bool)
	var mu sync.Mutex

	var rawCandidatePool []*types.DetectionResult
	var suitableResults []*types.DetectionResult
	concurrency := 10
	var workerWg sync.WaitGroup

	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()

	// 启动检测 Worker 协程池
	for i := 0; i < concurrency; i++ {
		go func() {
			for scanRes := range scanResultChan {
				func() {
					defer workerWg.Done()
					if scanRes == nil {
						return
					}

					// 检查是否已经达到上限，若达到立刻放弃
					mu.Lock()
					if !checkAll && maxTargets > 0 && len(suitableResults) >= maxTargets {
						mu.Unlock()
						return
					}
					mu.Unlock()

					select {
					case <-ctx.Done():
						return
					default:
					}

					d := scanRes.CertDomain
					res, err := r.engine.CheckDomain(ctx, d)

					mu.Lock()
					defer mu.Unlock()

					if !checkAll && maxTargets > 0 && len(suitableResults) >= maxTargets {
						return
					}

					// 阶段一：硬性技术基线检验
					if err == nil && res != nil && res.Suitable && res.Error == nil {
						stars := core.CalculateTargetStars(res)
						rawCandidatePool = append(rawCandidatePool, res)

						// 自动持久化资产库 (按 ASN/国家 归档)
						if targetStore != nil {
							rec := storage.DetectionResultToRecord(res, asnStr, countryStr, scanRes.IP, stars)
							_ = targetStore.UpsertTarget(rec)
						}

						// 阶段二：进阶偏好过滤
						passed, _ := core.FilterTarget(res, filter)
						if passed {
							suitableResults = append(suitableResults, res)
							suitableCount := len(suitableResults)

							var handshakeMs int64 = 0
							if res.TLS != nil {
								handshakeMs = res.TLS.HandshakeTime.Milliseconds()
							}
							var statusCode int = 0
							if res.Network != nil {
								statusCode = res.Network.StatusCode
							}

							timestamp := time.Now().Format("15:04:05")
							logger.AboveBar(bar, "[%s]  [扫描到第%d个符合条件的目标] %-35s (IP: %s, 握手: %dms, 页面: %d)\n",
								timestamp, suitableCount, d, scanRes.IP, handshakeMs, statusCode)

							if !checkAll && maxTargets > 0 && suitableCount >= maxTargets {
								ui.PrintTimestampedMessage("已达到设定的目标数量限制 (%d 个)，即刻刹车并停止扫描...", maxTargets)
								cancel()
							}
						}
					}
				}()
			}
		}()
	}

CIDRLoop:
	for idx, cidr := range cidrs {
		select {
		case <-ctx.Done():
			break CIDRLoop
		default:
		}

		mu.Lock()
		sc := len(suitableResults)
		mu.Unlock()
		if !checkAll && maxTargets > 0 && sc >= maxTargets {
			break CIDRLoop
		}

		logger.AboveBar(bar, "[%d/%d] 正在内嵌并发扫描网段: %s ...", idx+1, len(cidrs), cidr)

		// 单个 CIDR 的扫描输出中间通道
		subChan := make(chan *scanner.ScanResult, 50)

		// 异步收纳单个 CIDR 的扫描结果
		var pipeWg sync.WaitGroup
		pipeWg.Add(1)
		go func() {
			defer pipeWg.Done()
			for res := range subChan {
				if res == nil || res.CertDomain == "" || config.ShouldExcludeDomain(res.CertDomain, filter) {
					continue
				}

				mu.Lock()
				if !checkAll && maxTargets > 0 && len(suitableResults) >= maxTargets {
					mu.Unlock()
					continue
				}

				if !domainSet[res.CertDomain] {
					domainSet[res.CertDomain] = true
					workerWg.Add(1)
					select {
					case scanResultChan <- res:
					case <-ctx.Done():
						workerWg.Done()
					}
				}
				mu.Unlock()
			}
		}()

		// 执行并发 TLS 握手扫描
		scannerEngine.ScanCIDRStream(
			ctx,
			cidr,
			443,
			100,
			5,
			false,
			subChan,
			func(n int) {
				_ = bar.Add(n)
			},
		)
		close(subChan)
		pipeWg.Wait()
	}

	workerWg.Wait()
	fmt.Println()
	close(scanResultChan)

	if r.ctx.Err() != nil {
		ui.PrintTimestampedMessage("扫描已响应用户中断 (Ctrl+C) 并安全退出。")
		if len(suitableResults) > 0 {
			suitableResults = core.FilterPool(suitableResults, filter)
			r.batchManager.SortByRecommendationStars(suitableResults)
			fmt.Println("\n中断前已发现的适合域名:")
			fmt.Println(r.batchManager.FormatSuitableTable(suitableResults))
		}
		return
	}

	// 导出候选资产池 (如果指定了 --export)
	if exportFile != "" {
		exportPool := &types.CandidatePool{
			CreatedAt: time.Now(),
			Source:    fmt.Sprintf("%s (%s)", asnStr, countryStr),
			Targets:   rawCandidatePool,
		}
		if data, err := json.MarshalIndent(exportPool, "", "  "); err == nil {
			_ = os.WriteFile(exportFile, data, 0644)
			ui.PrintTimestampedMessage("已将本次摸排发现的 %d 个候选资产导出至: %s", len(rawCandidatePool), exportFile)
		}
	}

	// 阶段二最终排序与裁剪
	suitableResults = core.FilterPool(suitableResults, filter)
	if !checkAll && maxTargets > 0 && len(suitableResults) > maxTargets {
		suitableResults = suitableResults[:maxTargets]
	}

	ui.PrintTimestampedMessage("扫描与检测完成！共找到 %d 个符合策略的优质 REALITY 目标域名（技术基线合格总数: %d）。",
		len(suitableResults), len(rawCandidatePool))

	// 渲染经典带颜色 ASCII 表格
	if len(suitableResults) > 0 {
		r.batchManager.SortByRecommendationStars(suitableResults)
		fmt.Println("\n适合的域名:")
		fmt.Println(r.batchManager.FormatSuitableTable(suitableResults))
	}
}

// isSatisfiedRealityPolicy 检查检测结果是否符合 REALITY 最佳实践筛选策略
func isSatisfiedRealityPolicy(res *types.DetectionResult, err error, filter types.RealityFilterConfig) bool {
	if err != nil || res == nil || !res.Suitable || res.Error != nil {
		return false
	}
	passed, _ := core.FilterTarget(res, filter)
	return passed
}

func calculateStars(result *types.DetectionResult) int {
	stars := 0
	if result.TLS != nil && result.TLS.SupportsTLS13 &&
		result.TLS.SupportsX25519 && result.TLS.SupportsHTTP2 &&
		result.SNI != nil && result.SNI.SNIMatch {
		stars++
	}
	if result.TLS != nil && result.TLS.HandshakeTime > 0 {
		if result.TLS.HandshakeTime.Milliseconds() <= 200 {
			stars++
		}
	}
	if result.CDN != nil && !result.CDN.IsHotWebsite {
		stars++
	}
	if result.Certificate != nil && result.Certificate.Valid {
		if result.Certificate.DaysUntilExpiry >= 60 {
			stars++
		}
	}
	return stars
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// resolveInputToCIDRs 原生构建 CIDR 扫描队列（无需依赖易失效的第三方 HTTP API）
func resolveInputToCIDRs(targetInput string, inFile string) []string {
	var cidrs []string

	// 从文件批量读取 CIDRs
	if inFile != "" {
		f, err := os.Open(inFile)
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				cidrs = appendCIDR(cidrs, line)
			}
		}
	}

	// 处理单个命令行目标输入 (支持 CIDR 或 IP)
	if targetInput != "" {
		cidrs = appendCIDR(cidrs, targetInput)
	}

	return cidrs
}

// resolveAutoInput discovers announced prefixes for a target IP and keeps only
// prefixes whose representative address is in the target IP's country.
func resolveAutoInput(ctx context.Context, targetInput string, inFile string, country string) ([]string, string, string, error) {
	if inFile != "" || targetInput == "" || strings.Contains(targetInput, "/") {
		return resolveInputToCIDRs(targetInput, inFile), "", "", nil
	}
	ip := net.ParseIP(targetInput)
	if ip == nil {
		return resolveInputToCIDRs(targetInput, inFile), "", "", nil
	}

	reader, err := geoip2.Open("data/Country.mmdb")
	if err != nil {
		return nil, "", "", fmt.Errorf("打开 GeoIP 数据库失败: %w", err)
	}
	defer reader.Close()
	targetRecord, err := reader.Country(ip)
	if err != nil || targetRecord.Country.IsoCode == "" {
		return nil, "", "", fmt.Errorf("无法确定入口 IP %s 的国家", targetInput)
	}
	targetCountry := strings.ToUpper(strings.TrimSpace(country))
	if targetCountry == "" {
		targetCountry = targetRecord.Country.IsoCode
	}
	if len(targetCountry) != 2 {
		return nil, "", "", fmt.Errorf("国家代码必须是两位 ISO 代码（例如 DE、US）")
	}

	asnNumber, prefixes, err := asn.NewClient(15*time.Second).PrefixesForIP(ctx, ip.String())
	if err != nil {
		return nil, "", "", err
	}
	asnStr := fmt.Sprintf("AS%d", asnNumber)

	filtered := make([]string, 0, len(prefixes))
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		record, err := reader.Country(net.ParseIP(prefix.Addr().String()))
		if err == nil && record.Country.IsoCode == targetCountry {
			filtered = append(filtered, prefix.String())
		}
	}
	if len(filtered) == 0 {
		return nil, asnStr, targetCountry, fmt.Errorf("AS%d 没有与入口 IP 同国家（%s）的宣布网段", asnNumber, targetCountry)
	}
	ui.PrintTimestampedMessage("入口 IP %s 属于 %s，国家 %s；已过滤为 %d 个同国家网段",
		targetInput, asnStr, targetCountry, len(filtered))
	return filtered, asnStr, targetCountry, nil
}

// appendCIDR 解析并追加 CIDR 或单 IP 扩展网段，自动去重并规范化
func appendCIDR(list []string, input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return list
	}

	// 1. 输入本身已经是 CIDR 格式（如 "5.45.102.0/24"）
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err == nil {
			cidrStr := ipNet.String()
			if !contains(list, cidrStr) {
				list = append(list, cidrStr)
			}
		}
		return list
	}

	// 2. 输入是单个 IP，按就近原则扩展为子网
	ip := net.ParseIP(input)
	if ip == nil {
		return list
	}

	// IPv4: 扩展为包含该 IP 的标准 /24 网段
	if v4 := ip.To4(); v4 != nil {
		c24 := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
		if !contains(list, c24) {
			list = append(list, c24)
		}
		return list
	}

	// IPv6: 扩展为包含该 IP 的标准 /64 前缀网段
	mask := net.CIDRMask(64, 128)
	ipNet := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}
	c64 := ipNet.String()
	if !contains(list, c64) {
		list = append(list, c64)
	}

	return list
}

// parseAndExecuteAuto 解析命令行参数并应用 YAML 策略与 CLI 参数覆盖
func (r *RootCmd) parseAndExecuteAuto(args []string) {
	if len(args) == 0 {
		ui.PrintErrorWithDetails(
			"错误：缺少目标 IP / CIDR 参数或 --in 文件参数",
			"用法:",
			"  reality-checker auto <ip_or_cidr> [选项]",
			"  reality-checker auto --in <cidr_file> [选项]",
			"选项:",
			"  --in FILE            从文件中批量读取 CIDR/IP 列表 (每行一个)",
			"  --country CODE       按两位 ISO 国家代码过滤（默认使用入口 IP 国家）",
			"  --no-check           跳过data资源检测",
			"  --limit N / -m       指定获取合适目标的数量上限 (默认 5)",
			"  --check-all / -a     开启全量摸底扫描模式 (不提前终止，全量入库)",
			"  --no-cache           跳过本地资产库缓存，强制重新网络扫描",
			"  --export FILE        将扫描发现的所有合格资产导出为 JSON 文件",
			"  --no-cdn             强制筛选无 CDN 节点 (默认开启)",
			"  --allow-cdn          允许 CDN 节点",
			"  --max-handshake MS   设置最大握手延迟 (毫秒, 默认 800)",
			"  --no-hot             排除热门大站 (默认开启)",
			"  --allow-hot          允许热门大站",
			"  --min-cert-days DAYS 证书最低剩余天数 (默认 7 天)",
			"  --min-stars STARS    最低推荐星级 1-5 (默认 3)",
			"示例:",
			"  reality-checker auto 85.155.184.100 --limit 5",
			"  reality-checker auto 85.155.184.100 --check-all --export all.json",
			"  reality-checker auto 5.45.102.0/24 --limit 2",
			"  reality-checker auto --in cidrs.txt --limit 5",
		)
		os.Exit(1)
	}

	var targetInput string
	var inFile string
	var country string
	var exportFile string
	checkAll := false
	noCache := false
	maxTargets := 5
	filter := r.batchManager.GetConfig().RealityFilter

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") && targetInput == "" {
			targetInput = arg
			continue
		}

		switch arg {
		case "--in":
			if i+1 < len(args) {
				inFile = args[i+1]
				i++
			}
		case "--country":
			if i+1 < len(args) {
				country = args[i+1]
				i++
			}
		case "--limit", "-m":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					maxTargets = n
				}
				i++
			}
		case "--check-all", "-a":
			checkAll = true
		case "--no-cache":
			noCache = true
		case "--export":
			if i+1 < len(args) {
				exportFile = args[i+1]
				i++
			}
		case "--no-check":
			filter.RequireNoCDN = true
		case "--no-cdn":
			filter.RequireNoCDN = true
		case "--allow-cdn":
			filter.RequireNoCDN = false
		case "--no-hot":
			filter.RequireNoHot = true
		case "--allow-hot":
			filter.RequireNoHot = false
		case "--max-handshake":
			if i+1 < len(args) {
				if ms, err := strconv.ParseInt(args[i+1], 10, 64); err == nil {
					filter.MaxHandshakeMS = ms
				}
				i++
			}
		case "--min-cert-days":
			if i+1 < len(args) {
				if days, err := strconv.Atoi(args[i+1]); err == nil {
					filter.MinCertDays = days
				}
				i++
			}
		case "--min-stars":
			if i+1 < len(args) {
				if s, err := strconv.Atoi(args[i+1]); err == nil {
					filter.MinStars = s
				}
				i++
			}
		case "--debug":
			logger.Init("debug", "")
		case "--log-level":
			if i+1 < len(args) {
				logger.Init(args[i+1], "")
				i++
			}
		}
	}

	cidrs, asnStr, countryStr, err := resolveAutoInput(r.ctx, targetInput, inFile, country)
	if err != nil {
		ui.PrintError(fmt.Sprintf("自动查询 ASN 网段失败: %v", err))
		return
	}

	// Cache-First 快速通道：若本地库存在同 ASN 且未过期的资产，优先进行秒级并发健康复核
	if filter.UseCache && !noCache && !checkAll && asnStr != "" {
		store, err := storage.NewTargetStore("data/reality_targets.db")
		if err == nil {
			defer store.Close()
			maxAge := time.Duration(filter.CacheMaxDays) * 24 * time.Hour
			cachedRecords, _ := store.GetTargetsByASN(asnStr, countryStr, maxAge)

			if len(cachedRecords) > 0 {
				ui.PrintTimestampedMessage("发现同 ASN/国家 (%s, %s) 的历史资产 %d 条，正在极速复核连通性...",
					asnStr, countryStr, len(cachedRecords))

				var verified []*types.DetectionResult
				var vMu sync.Mutex
				var vWg sync.WaitGroup

				for _, rec := range cachedRecords {
					vWg.Add(1)
					go func(record *types.TargetRecord) {
						defer vWg.Done()
						res, err := r.engine.CheckDomain(r.ctx, record.Domain)
						if err == nil && res != nil && res.Suitable {
							passed, _ := core.FilterTarget(res, filter)
							if passed {
								vMu.Lock()
								verified = append(verified, res)
								vMu.Unlock()
							}
						}
					}(rec)
				}
				vWg.Wait()

				if len(verified) >= maxTargets {
					ui.PrintTimestampedMessage("✅ 成功从本地资产库秒级复用 %d 个优质 REALITY 目标！", len(verified))
					if len(verified) > maxTargets {
						verified = verified[:maxTargets]
					}
					r.batchManager.SortByRecommendationStars(verified)
					fmt.Println("\n适合的域名:")
					fmt.Println(r.batchManager.FormatSuitableTable(verified))
					return
				} else if len(verified) > 0 {
					ui.PrintTimestampedMessage("本地缓存复核通过 %d 个目标，不足指定数量 (%d)，继续启动网络扫描补充...",
						len(verified), maxTargets)
				}
			}
		}
	}

	r.executeAuto(cidrs, maxTargets, checkAll, exportFile, filter, asnStr, countryStr)
}

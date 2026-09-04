package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

// CalculateTotalIPs 计算一组 CIDR 或单 IP 的总数量（转发至 core.CalculateTotalIPs）
func CalculateTotalIPs(cidrs []string) int64 {
	return core.CalculateTotalIPs(cidrs)
}

// CalculateRemainingIPs 计算扣除已完成/部分完成断点网段后的剩余待扫描 IP 理论总数（转发至 core.CalculateRemainingIPs）
func CalculateRemainingIPs(cidrs []string, checkpoints map[string]*storage.CheckpointRecord) int64 {
	return core.CalculateRemainingIPs(cidrs, checkpoints)
}

// AutoScanCLIOptions 自动扫描命令行的参数配置
type AutoScanCLIOptions struct {
	CIDRs          []string
	MaxTargets     int
	CheckAll       bool
	ExportFile     string
	Filter         types.RealityFilterConfig
	ASN            string
	Country        string
	InitialResults []*types.DetectionResult
}

// executeAuto 组装 CLI 终端进度条与事件回调，调用 core.AutoScanner 执行扫描
func (r *RootCmd) executeAuto(opts AutoScanCLIOptions) {
	if len(opts.CIDRs) == 0 {
		ui.PrintError("错误：未提供有效的 CIDR 扫描网段")
		return
	}

	scannerEngine := scanner.NewScanner()
	defer scannerEngine.Close()

	targetStore, err := storage.NewTargetStore("data/reality_targets.db")
	if err != nil {
		ui.PrintTimestampedMessage("⚠️ 本地资产数据库初始化失败: %v (将使用内存模式)", err)
	} else {
		defer targetStore.Close()
	}

	taskKey := ""
	if opts.ASN != "" && opts.Country != "" {
		taskKey = fmt.Sprintf("%s_%s", opts.ASN, opts.Country)
	}

	grandTotalIPCount := core.CalculateTotalIPs(opts.CIDRs)
	var checkpointsMap map[string]*storage.CheckpointRecord
	if opts.CheckAll && targetStore != nil && taskKey != "" && !opts.Filter.NoResume {
		checkpointsMap, _ = targetStore.GetCheckpoints(taskKey)
	}
	remainingIPCount := core.CalculateRemainingIPs(opts.CIDRs, checkpointsMap)
	alreadyScannedIPCount := grandTotalIPCount - remainingIPCount

	bar := progressbar.NewOptions64(grandTotalIPCount,
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
	if alreadyScannedIPCount > 0 {
		_ = bar.Set64(alreadyScannedIPCount)
	}

	ui.PrintTimestampedMessage("开启内嵌自动化扫描与检测模式 (Native Engine)...")
	if opts.CheckAll {
		ui.PrintTimestampedMessage("模式: 全量摸底扫描 (--check-all)，将收集并存档所有合规资产入库")
	}

	nonDefaults := formatNonDefaultFilters(opts.Filter)
	if len(nonDefaults) > 0 {
		ui.PrintTimestampedMessage("检测到自定义非默认过滤条件: [%s]", strings.Join(nonDefaults, ", "))
	} else {
		ui.PrintTimestampedMessage("应用 REALITY 选型策略: [全部使用推荐默认值]")
	}

	ui.PrintTimestampedMessage("待扫描网段总数: %d 个。排序如下:", len(opts.CIDRs))
	for i, c := range opts.CIDRs {
		if i < 5 {
			fmt.Printf("  [%d] %s\n", i+1, c)
		}
	}
	if len(opts.CIDRs) > 5 {
		fmt.Printf("  ...以及其余 %d 个网段\n", len(opts.CIDRs)-5)
	}

	var lastUpdate time.Time
	var updateMu sync.Mutex

	events := core.AutoScanEvents{
		OnIPScanned: func(delta int, currentCIDR string, currentIP string, currentIdx int, totalCIDRs int) {
			_ = bar.Add(delta)
			updateMu.Lock()
			if time.Since(lastUpdate) > 150*time.Millisecond {
				lastUpdate = time.Now()
				bar.Describe(fmt.Sprintf("[cyan][网段 %d/%d: %s | 探测: %s][reset]", currentIdx, totalCIDRs, currentCIDR, currentIP))
			}
			updateMu.Unlock()
		},
		OnTargetFound: func(res *types.DetectionResult, count int, ip string, handshakeMs int64, statusCode int) {
			timestamp := time.Now().Format("15:04:05")
			logger.AboveBar(bar, "[%s]  [扫描到第%d个符合条件的目标] %-35s (IP: %s, 握手: %dms, 页面: %d)\n",
				timestamp, count, res.Domain, ip, handshakeMs, statusCode)
		},
		OnLimitHit: func(maxTargets int) {
			ui.PrintTimestampedMessage("已达到设定的目标数量限制 (%d 个)，即刻刹车并停止扫描...", maxTargets)
		},
		OnCIDRScanStart: func(currentIdx int, totalCIDRs int, cidr string, resumeIP string) {
			if resumeIP != "" {
				logger.AboveBar(bar, "[%d/%d] 正在并发扫描网段: %s (从断点 IP: %s 继续)...", currentIdx, totalCIDRs, cidr, resumeIP)
			} else {
				logger.AboveBar(bar, "[%d/%d] 正在并发扫描网段: %s ...", currentIdx, totalCIDRs, cidr)
			}
		},
		OnLog: func(msg string) {
			ui.PrintTimestampedMessage("%s", msg)
		},
	}

	scannerCore := core.NewAutoScanner(
		r.engine,
		targetStore,
		scannerEngine,
		core.AutoScanConfig{
			CIDRs:          opts.CIDRs,
			MaxTargets:     opts.MaxTargets,
			CheckAll:       opts.CheckAll,
			Filter:         opts.Filter,
			ASN:            opts.ASN,
			Country:        opts.Country,
			InitialResults: opts.InitialResults,
		},
		events,
	)

	res, err := scannerCore.Run(r.ctx)
	fmt.Println()

	if err != nil {
		if errors.Is(err, core.ErrAllCompleted) {
			ui.PrintTimestampedMessage("✅ 全量摸排任务 (%s) 的所有网段此前已全部扫描完成！如需重新全量扫描请指定 --reset-scan", taskKey)
			return
		}
		ui.PrintError(fmt.Sprintf("扫描失败: %v", err))
		return
	}

	if res.IsInterrupted {
		ui.PrintTimestampedMessage("扫描已响应用户中断 (Ctrl+C) 并安全退出。")
		if opts.CheckAll && taskKey != "" {
			ui.PrintTimestampedMessage("💡 已自动保存当前网段与当前 IP 扫描断点进度，再次运行时将无缝续传。")
		}
		if len(res.SuitableResults) > 0 {
			r.batchManager.SortByRecommendationStars(res.SuitableResults)
			fmt.Println("\n中断前已发现的适合域名:")
			fmt.Println(r.batchManager.FormatSuitableTable(res.SuitableResults))
		}
		return
	}

	// 导出候选资产池 (如果指定了 --export)
	if opts.ExportFile != "" {
		exportPool := &types.CandidatePool{
			CreatedAt: time.Now(),
			Source:    fmt.Sprintf("%s (%s)", opts.ASN, opts.Country),
			Targets:   res.RawCandidatePool,
		}
		if data, err := json.MarshalIndent(exportPool, "", "  "); err == nil {
			_ = os.WriteFile(opts.ExportFile, data, 0644)
			ui.PrintTimestampedMessage("已将本次摸排发现的 %d 个候选资产导出至: %s", len(res.RawCandidatePool), opts.ExportFile)
		}
	}

	ui.PrintTimestampedMessage("扫描与检测完成！共找到 %d 个符合策略的优质 REALITY 目标域名（技术基线合格总数: %d）。",
		len(res.SuitableResults), len(res.RawCandidatePool))

	// 渲染经典带颜色 ASCII 表格
	if len(res.SuitableResults) > 0 {
		r.batchManager.SortByRecommendationStars(res.SuitableResults)
		fmt.Println("\n适合的域名:")
		fmt.Println(r.batchManager.FormatSuitableTable(res.SuitableResults))
	}
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
func resolveInputToCIDRs(targetInput string, inFile string, filter types.RealityFilterConfig) []string {
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
				cidrs = appendCIDR(cidrs, line, filter)
			}
		}
	}

	// 处理单个命令行目标输入 (支持 CIDR 或 IP)
	if targetInput != "" {
		cidrs = appendCIDR(cidrs, targetInput, filter)
	}

	return cidrs
}

// resolveAutoInput discovers announced prefixes for a target IP and keeps only
// prefixes whose representative address is in the target IP's country and matches IPv4/IPv6 filter.
func resolveAutoInput(ctx context.Context, targetInput string, inFile string, country string, filter types.RealityFilterConfig) ([]string, string, string, error) {
	if inFile != "" || targetInput == "" || strings.Contains(targetInput, "/") {
		return resolveInputToCIDRs(targetInput, inFile, filter), "", "", nil
	}
	ip := net.ParseIP(targetInput)
	if ip == nil {
		return resolveInputToCIDRs(targetInput, inFile, filter), "", "", nil
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
		// 协议族过滤
		if filter.IPv4Only && !prefix.Addr().Is4() {
			continue
		}
		if filter.IPv6Only && !prefix.Addr().Is6() {
			continue
		}

		record, err := reader.Country(net.ParseIP(prefix.Addr().String()))
		if err == nil && record.Country.IsoCode == targetCountry {
			filtered = append(filtered, prefix.String())
		}
	}
	if len(filtered) == 0 {
		return nil, asnStr, targetCountry, fmt.Errorf("AS%d 没有与入口 IP 同国家（%s）且符合 IP 协议族限制的宣布网段", asnNumber, targetCountry)
	}
	ui.PrintTimestampedMessage("入口 IP %s 属于 %s，国家 %s；已过滤为 %d 个同国家网段",
		targetInput, asnStr, targetCountry, len(filtered))
	return filtered, asnStr, targetCountry, nil
}

// appendCIDR 解析并追加 CIDR 或单 IP 扩展网段，自动去重并规范化
func appendCIDR(list []string, input string, filter types.RealityFilterConfig) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return list
	}

	// 1. 输入本身已经是 CIDR 格式（如 "5.45.102.0/24"）
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err == nil {
			isIPv4 := ipNet.IP.To4() != nil
			if filter.IPv4Only && !isIPv4 {
				return list
			}
			if filter.IPv6Only && isIPv4 {
				return list
			}
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
		if filter.IPv6Only {
			return list
		}
		c24 := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
		if !contains(list, c24) {
			list = append(list, c24)
		}
		return list
	}

	// IPv6: 扩展为包含该 IP 的标准 /64 前缀网段
	if filter.IPv4Only {
		return list
	}
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
			"  --check-all / -a     开启全量摸底扫描模式 (不提前终止，全量入库，支持断点续传)",
			"  --reset-scan         重置断点记录，从第 1 个网段重新扫描",
			"  --threads N / -t     设置网络扫描并发协程数 (默认 200，高性能机器可设 500-1000)",
			"  --timeout SEC        单 IP 握手超时秒数 (默认 3 秒，死 IP 快速熔断建议 1-2 秒)",
			"  --no-cache           跳过本地资产库缓存，强制重新网络扫描",
			"  --recheck            对本地资产库命中目标发起在线网络复核",
			"  --ipv4-only / -4     仅拉取与扫描 IPv4 网段",
			"  --ipv6-only / -6     仅拉取与扫描 IPv6 网段",
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
			"  reality-checker auto 59.110.190.69 --check-all --threads 500 --timeout 2",
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
		case "--threads", "-t":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil && t > 0 {
					filter.ScanThreads = t
				}
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				if to, err := strconv.Atoi(args[i+1]); err == nil && to > 0 {
					filter.ScanTimeout = to
				}
				i++
			}
		case "--check-all", "-a":
			checkAll = true
		case "--reset-scan", "--no-resume":
			filter.NoResume = true
		case "--no-cache":
			noCache = true
		case "--recheck", "--verify-cache":
			filter.VerifyCache = true
		case "--no-recheck":
			filter.VerifyCache = false
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
		case "--ipv4-only", "-4":
			filter.IPv4Only = true
			filter.IPv6Only = false
		case "--ipv6-only", "-6":
			filter.IPv6Only = true
			filter.IPv4Only = false
		case "--debug":
			logger.Init("debug", "")
		case "--log-level":
			if i+1 < len(args) {
				logger.Init(args[i+1], "")
				i++
			}
		}
	}

	cidrs, asnStr, countryStr, err := resolveAutoInput(r.ctx, targetInput, inFile, country, filter)
	if err != nil {
		ui.PrintError(fmt.Sprintf("自动查询 ASN 网段失败: %v", err))
		return
	}

	// Cache-First 快速通道：若本地库存在同 ASN 且未过期的资产，优先进行秒级直出（默认 0 网络请求，可加 --recheck 在线复核）
	var cachedVerified []*types.DetectionResult
	if filter.UseCache && !noCache && !checkAll && asnStr != "" {
		store, err := storage.NewTargetStore("data/reality_targets.db")
		if err == nil {
			defer store.Close()
			maxAge := time.Duration(filter.CacheMaxDays) * 24 * time.Hour
			cachedRecords, _ := store.GetTargetsByASN(asnStr, countryStr, maxAge)

			if len(cachedRecords) > 0 {
				if !filter.VerifyCache {
					// 默认模式：直接使用本地历史参数，0 网络请求极速秒出
					for _, rec := range cachedRecords {
						res := storage.RecordToDetectionResult(rec)
						if res != nil {
							passed, _ := core.FilterTarget(res, filter)
							if passed {
								cachedVerified = append(cachedVerified, res)
							}
						}
					}

					if len(cachedVerified) >= maxTargets {
						ui.PrintTimestampedMessage("✅ 从本地资产库秒级命中 %d 个历史资产（0 网络延迟，极速直出）！如需在线连通性复核可添加 --recheck", len(cachedVerified))
						cachedVerified = core.FilterPool(cachedVerified, filter)
						if len(cachedVerified) > maxTargets {
							cachedVerified = cachedVerified[:maxTargets]
						}
						r.batchManager.SortByRecommendationStars(cachedVerified)
						fmt.Println("\n适合的域名:")
						fmt.Println(r.batchManager.FormatSuitableTable(cachedVerified))
						return
					} else if len(cachedVerified) > 0 {
						ui.PrintTimestampedMessage("本地资产库命中 %d 个目标，不足指定数量 (%d)，已预置并启动网络扫描补充...",
							len(cachedVerified), maxTargets)
					}
				} else {
					// 传入了 --recheck / --verify-cache：在线并发复核连通性
					ui.PrintTimestampedMessage("发现同 ASN/国家 (%s, %s) 的历史资产 %d 条，正在在线并发复核连通性...",
						asnStr, countryStr, len(cachedRecords))

					var vMu sync.Mutex
					var vWg sync.WaitGroup
					sem := make(chan struct{}, 15) // 控制并发数为 15，防止瞬间并发大量 HTTP 请求导致 Windows Socket 耗尽

					checkCtx, cancelCheck := context.WithTimeout(r.ctx, 6*time.Second)
					defer cancelCheck()

					for _, rec := range cachedRecords {
						select {
						case <-checkCtx.Done():
							break
						default:
						}

						vWg.Add(1)
						go func(record *types.TargetRecord) {
							defer vWg.Done()

							select {
							case sem <- struct{}{}:
								defer func() { <-sem }()
							case <-checkCtx.Done():
								return
							}

							res, err := r.engine.CheckDomain(checkCtx, record.Domain)
							if err == nil && res != nil && res.Suitable {
								passed, _ := core.FilterTarget(res, filter)
								if passed {
									vMu.Lock()
									cachedVerified = append(cachedVerified, res)
									vMu.Unlock()
								}
							}
						}(rec)
					}
					vWg.Wait()

					if r.ctx.Err() != nil {
						ui.PrintTimestampedMessage("任务已被用户中断 (Ctrl+C)。")
						return
					}

					if len(cachedVerified) >= maxTargets {
						ui.PrintTimestampedMessage("✅ 成功从本地资产库复核通过 %d 个优质 REALITY 目标！", len(cachedVerified))
						cachedVerified = core.FilterPool(cachedVerified, filter)
						if len(cachedVerified) > maxTargets {
							cachedVerified = cachedVerified[:maxTargets]
						}
						r.batchManager.SortByRecommendationStars(cachedVerified)
						fmt.Println("\n适合的域名:")
						fmt.Println(r.batchManager.FormatSuitableTable(cachedVerified))
						return
					} else if len(cachedVerified) > 0 {
						ui.PrintTimestampedMessage("本地缓存复核通过 %d 个目标，不足指定数量 (%d)，已预置并继续启动网络扫描补充...",
							len(cachedVerified), maxTargets)
					}
				}
			}
		}
	}

	r.executeAuto(AutoScanCLIOptions{
		CIDRs:          cidrs,
		MaxTargets:     maxTargets,
		CheckAll:       checkAll,
		ExportFile:     exportFile,
		Filter:         filter,
		ASN:            asnStr,
		Country:        countryStr,
		InitialResults: cachedVerified,
	})
}

// formatNonDefaultFilters 格式化输出用户自定义/非默认的 REALITY 选型策略
func formatNonDefaultFilters(filter types.RealityFilterConfig) []string {
	def := config.GetDefaultConfig().RealityFilter
	var diffs []string

	if filter.RequireNoCN != def.RequireNoCN {
		if filter.RequireNoCN {
			diffs = append(diffs, "排除国内站点 (require_no_cn=true)")
		} else {
			diffs = append(diffs, "允许国内站点 (require_no_cn=false)")
		}
	}
	if filter.CheckGFW != def.CheckGFW {
		diffs = append(diffs, fmt.Sprintf("GFW黑名单=%v", filter.CheckGFW))
	}
	if filter.IPv4Only != def.IPv4Only && filter.IPv4Only {
		diffs = append(diffs, "仅IPv4 (ipv4_only=true)")
	}
	if filter.IPv6Only != def.IPv6Only && filter.IPv6Only {
		diffs = append(diffs, "仅IPv6 (ipv6_only=true)")
	}
	if filter.RequireNoCDN != def.RequireNoCDN {
		diffs = append(diffs, fmt.Sprintf("非CDN限制=%v", filter.RequireNoCDN))
	}
	if filter.ScanThreads != def.ScanThreads && filter.ScanThreads > 0 {
		diffs = append(diffs, fmt.Sprintf("并发协程=%d (默认%d)", filter.ScanThreads, def.ScanThreads))
	}
	if filter.ScanTimeout != def.ScanTimeout && filter.ScanTimeout > 0 {
		diffs = append(diffs, fmt.Sprintf("单IP超时=%d秒 (默认%d秒)", filter.ScanTimeout, def.ScanTimeout))
	}
	if filter.MaxHandshakeMS != def.MaxHandshakeMS && filter.MaxHandshakeMS > 0 {
		diffs = append(diffs, fmt.Sprintf("最大握手延迟=%dms", filter.MaxHandshakeMS))
	}
	if filter.RequireNoHot != def.RequireNoHot {
		diffs = append(diffs, fmt.Sprintf("排除热门大站=%v", filter.RequireNoHot))
	}
	if filter.MinCertDays != def.MinCertDays && filter.MinCertDays > 0 {
		diffs = append(diffs, fmt.Sprintf("最小证书天数=%d天", filter.MinCertDays))
	}
	if filter.MinStars != def.MinStars && filter.MinStars > 0 {
		diffs = append(diffs, fmt.Sprintf("最低推荐星级=%d星", filter.MinStars))
	}
	if filter.RequireNoDefaultPage != def.RequireNoDefaultPage {
		diffs = append(diffs, fmt.Sprintf("排除默认欢迎页=%v", filter.RequireNoDefaultPage))
	}
	if len(filter.IncludeSuffixes) > 0 {
		diffs = append(diffs, fmt.Sprintf("白名单后缀=%v", filter.IncludeSuffixes))
	}
	if len(filter.ExcludeSuffixes) > 0 {
		defaultSet := make(map[string]bool)
		for _, s := range def.ExcludeSuffixes {
			defaultSet[s] = true
		}
		var customEx []string
		for _, s := range filter.ExcludeSuffixes {
			if !defaultSet[s] {
				customEx = append(customEx, s)
			}
		}
		if len(customEx) > 0 {
			diffs = append(diffs, fmt.Sprintf("附加排除后缀=%v", customEx))
		}
	}
	if len(filter.ExcludeStatus) > 0 {
		defaultStatus := make(map[int]bool)
		for _, st := range def.ExcludeStatus {
			defaultStatus[st] = true
		}
		var customStatus []int
		for _, st := range filter.ExcludeStatus {
			if !defaultStatus[st] {
				customStatus = append(customStatus, st)
			}
		}
		if len(customStatus) > 0 {
			diffs = append(diffs, fmt.Sprintf("附加排除状态码=%v", customStatus))
		}
	}

	return diffs
}

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/config"
	"RealityChecker/internal/core"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"
)

// executePipe 从标准输入(Stdin)流式读取 CSV 数据或域名，进行实时并行检测并输出彩色表格
func (r *RootCmd) executePipe() {
	ui.PrintTimestampedMessage("开启管道流式检测模式 (Pipe Mode)...")

	filter := types.RealityFilterConfig{}
	if r.batchManager != nil && r.batchManager.GetConfig() != nil {
		filter = r.batchManager.GetConfig().RealityFilter
	}

	scanner := bufio.NewScanner(os.Stdin)

	// 域名管道与去重集合
	domainChan := make(chan string, 100)
	domainSet := make(map[string]bool)
	var mu sync.Mutex

	var suitableResults []*types.DetectionResult
	concurrency := 10
	var wg sync.WaitGroup

	// 启动 Worker 协程池
	for i := 0; i < concurrency; i++ {
		go func() {
			for domain := range domainChan {
				func() {
					defer wg.Done()

					res, err := r.engine.CheckDomain(r.ctx, domain)

					mu.Lock()
					defer mu.Unlock()

					if err == nil && res != nil && res.Suitable && res.Error == nil {
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
							fmt.Printf("[%s] ★ [可用 REALITY 目标 #%d] %-35s (握手: %dms, 页面: %d)\n",
								timestamp, suitableCount, domain, handshakeMs, statusCode)
						}
					}
				}()
			}
		}()
	}

	certDomainIdx := -1
	headerParsed := false

	// 逐行解析 Stdin
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 检查是否为 CSV 表头
		if !headerParsed && strings.Contains(strings.ToUpper(line), "CERT_DOMAIN") {
			parts := strings.Split(line, ",")
			for idx, col := range parts {
				if strings.ToUpper(strings.TrimSpace(col)) == "CERT_DOMAIN" {
					certDomainIdx = idx
					break
				}
			}
			headerParsed = true
			continue
		}

		var candidateDomain string

		// 判断是 CSV 行还是单域名
		if strings.Contains(line, ",") {
			parts := strings.Split(line, ",")
			targetIdx := certDomainIdx
			if targetIdx == -1 || targetIdx >= len(parts) {
				// 容错: 查找包含 '.' 的可能域名列
				for _, part := range parts {
					p := strings.Trim(strings.TrimSpace(part), "\"")
					if strings.Contains(p, ".") && !strings.HasPrefix(p, "TLS") && !config.ShouldExcludeDomain(p, filter) {
						candidateDomain = p
						break
					}
				}
			} else {
				candidateDomain = strings.Trim(strings.TrimSpace(parts[targetIdx]), "\"")
			}
		} else {
			candidateDomain = strings.Trim(strings.TrimSpace(line), "\"")
		}

		if candidateDomain == "" || config.ShouldExcludeDomain(candidateDomain, filter) {
			continue
		}

		// 内存去重并派发给 Worker
		mu.Lock()
		seen := domainSet[candidateDomain]
		if !seen {
			domainSet[candidateDomain] = true
			wg.Add(1)
			domainChan <- candidateDomain
		}
		mu.Unlock()
	}

	wg.Wait()
	close(domainChan)

	if err := scanner.Err(); err != nil {
		ui.PrintError(fmt.Sprintf("读取管道输入错误: %v", err))
	}

	ui.PrintTimestampedMessage("管道流式检测结束。共找到 %d 个适合的 REALITY 目标域名。", len(suitableResults))

	// 渲染经典带颜色 ASCII 表格
	if len(suitableResults) > 0 {
		r.batchManager.SortByRecommendationStars(suitableResults)
		fmt.Println("\n适合的域名:")
		fmt.Println(r.batchManager.FormatSuitableTable(suitableResults))
	}
}

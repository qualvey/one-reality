package core

import (
	"fmt"
	"sort"
	"strings"

	"RealityChecker/internal/config"
	"RealityChecker/internal/types"
)

// FilterTarget 纯内存进阶偏好过滤（阶段二）：评估一个候选目标是否满足用户的进阶策略
func FilterTarget(target *types.DetectionResult, filter types.RealityFilterConfig) (bool, string) {
	if target == nil {
		return false, "目标为空"
	}

	// 1. 基础硬性条件必须满足
	if !target.Suitable || target.Error != nil {
		if target.Error != nil {
			return false, target.Error.Error()
		}
		return false, "未通过阶段一硬性技术基线"
	}

	domainToCheck := target.Domain
	if target.Network != nil && target.Network.FinalDomain != "" {
		domainToCheck = target.Network.FinalDomain
	}

	// 2. 域名白名单后缀 (include_suffixes) 与 黑名单 (exclude_suffixes / exclude_domains / exclude_patterns)
	if config.ShouldExcludeDomain(domainToCheck, filter) {
		return false, "域名或后缀不符合偏好策略"
	}

	// 3. CDN 过滤
	if filter.RequireNoCDN && target.CDN != nil && target.CDN.IsCDN {
		provider := target.CDN.CDNProvider
		if provider == "" {
			provider = "未知CDN"
		}
		return false, fmt.Sprintf("使用了CDN (%s)", provider)
	}

	// 4. 热门网站过滤
	if filter.RequireNoHot && target.CDN != nil && target.CDN.IsHotWebsite {
		return false, "属于超级热门大站"
	}

	// 5. Nginx / Web 默认页过滤
	if filter.RequireNoDefaultPage && target.Network != nil && target.Network.IsDefaultPage {
		typeName := target.Network.DefaultPageType
		if typeName == "" {
			typeName = "Nginx"
		}
		reason := target.Network.DefaultPageReason
		if reason == "" {
			reason = "默认返回页"
		}
		return false, fmt.Sprintf("检测到%s默认页 (%s)", typeName, reason)
	}

	// 6. 握手时间延迟上限
	if filter.MaxHandshakeMS > 0 && target.TLS != nil && target.TLS.HandshakeTime > 0 {
		handshakeMs := target.TLS.HandshakeTime.Milliseconds()
		if handshakeMs > filter.MaxHandshakeMS {
			return false, fmt.Sprintf("握手延迟超限 (%dms > %dms)", handshakeMs, filter.MaxHandshakeMS)
		}
	}

	// 7. 证书剩余有效天数下限
	if filter.MinCertDays > 0 && target.Certificate != nil && target.Certificate.Valid {
		if target.Certificate.DaysUntilExpiry < filter.MinCertDays {
			return false, fmt.Sprintf("证书剩余天数不足 (%d天 < %d天)", target.Certificate.DaysUntilExpiry, filter.MinCertDays)
		}
	}

	// 8. HTTP 状态码过滤
	if target.Network != nil && target.Network.Accessible {
		if config.ShouldExcludeStatusCode(target.Network.StatusCode, filter) {
			return false, fmt.Sprintf("状态码被排除: %d", target.Network.StatusCode)
		}
	}

	// 9. 最低推荐星级门槛
	stars := CalculateTargetStars(target)
	if filter.MinStars > 0 && stars < filter.MinStars {
		return false, fmt.Sprintf("星级未达门槛 (%d星 < %d星)", stars, filter.MinStars)
	}

	return true, ""
}

// FilterPool 对资产池进行纯内存批量偏好二次过滤（阶段二）
func FilterPool(pool []*types.DetectionResult, filter types.RealityFilterConfig) []*types.DetectionResult {
	var suitable []*types.DetectionResult
	seen := make(map[string]bool)

	for _, target := range pool {
		if target == nil {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(target.Domain))
		if key == "" || seen[key] {
			continue
		}

		passed, _ := FilterTarget(target, filter)
		if passed {
			seen[key] = true
			suitable = append(suitable, target)
		}
	}

	// 智能排序
	SortTargets(suitable)
	return suitable
}

// CalculateTargetStars 计算域名的推荐星级 (1~5 星)
func CalculateTargetStars(result *types.DetectionResult) int {
	if result == nil {
		return 0
	}
	stars := 0

	// 1. TLS 硬性指标 (TLS 1.3 + X25519 + H2 + SNI 匹配)
	if result.TLS != nil && result.TLS.SupportsTLS13 &&
		result.TLS.SupportsX25519 && result.TLS.SupportsHTTP2 &&
		result.SNI != nil && result.SNI.SNIMatch {
		stars++
	}

	// 2. 极速延迟 (<= 200ms)
	if result.TLS != nil && result.TLS.HandshakeTime > 0 {
		if result.TLS.HandshakeTime.Milliseconds() <= 200 {
			stars++
		}
	}

	// 3. 非 CDN 站点
	if result.CDN == nil || !result.CDN.IsCDN {
		stars++
	}

	// 4. 非热门大厂站点
	if result.CDN != nil && !result.CDN.IsHotWebsite {
		stars++
	}

	// 5. 证书充足 (>= 60天)
	if result.Certificate != nil && result.Certificate.Valid {
		if result.Certificate.DaysUntilExpiry >= 60 {
			stars++
		}
	}

	return stars
}

// SortTargets 按星级升序/握手延迟对结果进行排版排序
func SortTargets(results []*types.DetectionResult) {
	sort.Slice(results, func(i, j int) bool {
		starsI := CalculateTargetStars(results[i])
		starsJ := CalculateTargetStars(results[j])
		if starsI != starsJ {
			return starsI < starsJ // 升序：1星在前，5星在后（便于表格自上而下呈现）
		}
		// 星级相同时按握手延迟升序
		var msI, msJ int64
		if results[i].TLS != nil {
			msI = results[i].TLS.HandshakeTime.Milliseconds()
		}
		if results[j].TLS != nil {
			msJ = results[j].TLS.HandshakeTime.Milliseconds()
		}
		return msI < msJ
	})
}

package core

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"RealityChecker/internal/detectors"
	"RealityChecker/internal/network"
	"RealityChecker/internal/types"
)

// PipelineProfile 检测流水线编排画像
type PipelineProfile string

const (
	// ProfileFast 吞吐优先基线模式 (海量网段全网扫描场景)
	// 聚焦硬性技术基线：GFW 内存名单、TLS 1.3 / X25519 / H2 / 证书有效性 / CDN 识别、热门网站内存对比
	// 跳过多重 HTTP 重定向、状态码探测与重复 DNS 反查，大幅降低大吞吐扫描延迟
	ProfileFast PipelineProfile = "fast"

	// ProfileStandard 标准检测模式 (默认模式)
	// 包含完整的 8 个检测阶段：GFW封锁、HTTP重定向、HTTP状态码、DNS解析、地理位置检测与核对、综合TLS、热门网站
	ProfileStandard PipelineProfile = "standard"

	// ProfileThorough 深度审计模式
	// 包含标准模式全部阶段，可支持深入语义与严格规则审计
	ProfileThorough PipelineProfile = "thorough"
)

// Pipeline 检测流水线
type Pipeline struct {
	profile     PipelineProfile
	stages      []types.DetectionStage
	config      *types.Config
	earlyExit   bool
	connections *network.ConnectionManager
	mu          sync.RWMutex
}

// PipelineOption 配置选项
type PipelineOption func(*Pipeline)

// WithProfile 设置流水线模式
func WithProfile(profile PipelineProfile) PipelineOption {
	return func(p *Pipeline) {
		p.profile = profile
	}
}

// WithEarlyExit 设置是否在阶段失败时提前退出
func WithEarlyExit(earlyExit bool) PipelineOption {
	return func(p *Pipeline) {
		p.earlyExit = earlyExit
	}
}

// WithStages 显式指定流水线阶段
func WithStages(stages ...types.DetectionStage) PipelineOption {
	return func(p *Pipeline) {
		p.stages = make([]types.DetectionStage, len(stages))
		copy(p.stages, stages)
		sort.Slice(p.stages, func(i, j int) bool {
			return p.stages[i].Priority() < p.stages[j].Priority()
		})
	}
}

// NewPipeline 创建新的检测流水线 (默认使用 ProfileStandard 保持向下兼容)
func NewPipeline(connections *network.ConnectionManager, config *types.Config) *Pipeline {
	return NewPipelineWithProfile(connections, config, ProfileStandard)
}

// NewPipelineWithProfile 根据指定画像创建检测流水线
func NewPipelineWithProfile(connections *network.ConnectionManager, config *types.Config, profile PipelineProfile) *Pipeline {
	if connections == nil {
		connections = network.NewConnectionManager(config)
	}
	p := &Pipeline{
		profile:     profile,
		config:      config,
		earlyExit:   true,
		connections: connections,
	}

	p.loadStagesForProfile(profile)
	return p
}

// NewPipelineWithOptions 使用自定义选项构建检测流水线
func NewPipelineWithOptions(connections *network.ConnectionManager, config *types.Config, opts ...PipelineOption) *Pipeline {
	if connections == nil {
		connections = network.NewConnectionManager(config)
	}
	p := &Pipeline{
		profile:     ProfileStandard,
		config:      config,
		earlyExit:   true,
		connections: connections,
	}

	// 先按默认 profile 加载阶段
	p.loadStagesForProfile(p.profile)

	// 应用选项
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}

	return p
}

// loadStagesForProfile 根据画像装配对应阶段
func (p *Pipeline) loadStagesForProfile(profile PipelineProfile) {
	switch profile {
	case ProfileFast:
		// 吞吐优先：仅保留内存级与核心 TLS/证书/CDN 必须检测
		p.stages = []types.DetectionStage{
			detectors.NewBlockedStage(),          // 1. GFW 内存黑名单快速过滤
			detectors.NewComprehensiveTLSStage(), // 2. 综合 TLS 检测 (TLS1.3、X25519、H2、证书合规、CDN识别)
			detectors.NewHotWebsiteStage(),       // 3. 热门网站快速内存识别
		}
	case ProfileThorough:
		fallthrough
	case ProfileStandard:
		fallthrough
	default:
		p.profile = ProfileStandard
		p.stages = []types.DetectionStage{
			detectors.NewBlockedStage(),          // 1. 被墙检测 (最高优先级)
			detectors.NewRedirectStage(),         // 2. 重定向检测
			detectors.NewStatusCheckStage(),      // 3. 状态码检查
			detectors.NewIPResolverStage(),       // 4. IP解析
			detectors.NewLocationStage(),         // 5. 地理位置检测
			detectors.NewLocationCheckStage(),    // 6. 地理位置检查
			detectors.NewComprehensiveTLSStage(), // 7. 综合TLS检测 (TLS1.3、X25519、H2、SNI、证书、CDN)
			detectors.NewHotWebsiteStage(),       // 8. 热门网站检测
		}
	}

	// 按优先级严格排序
	sort.Slice(p.stages, func(i, j int) bool {
		return p.stages[i].Priority() < p.stages[j].Priority()
	})
}

// Profile 返回当前流水线编排画像
func (p *Pipeline) Profile() PipelineProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.profile
}

// SetProfile 动态切换流水线编排画像并重新装载阶段
func (p *Pipeline) SetProfile(profile PipelineProfile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.profile = profile
	p.loadStagesForProfile(profile)
}

// StageNames 获取当前所有激活的检测阶段名称列表
func (p *Pipeline) StageNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, len(p.stages))
	for i, stage := range p.stages {
		names[i] = stage.Name()
	}
	return names
}

// HasStage 查询指定阶段是否已启用
func (p *Pipeline) HasStage(name string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, stage := range p.stages {
		if stage.Name() == name {
			return true
		}
	}
	return false
}

// EnableStage 动态启用或禁用某个阶段
func (p *Pipeline) EnableStage(name string, enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	has := false
	for _, stage := range p.stages {
		if stage.Name() == name {
			has = true
			break
		}
	}

	if enabled && !has {
		// 根据名称实例化补充该阶段
		var newStage types.DetectionStage
		switch name {
		case "blocked":
			newStage = detectors.NewBlockedStage()
		case "redirect":
			newStage = detectors.NewRedirectStage()
		case "status_check":
			newStage = detectors.NewStatusCheckStage()
		case "ip_resolver":
			newStage = detectors.NewIPResolverStage()
		case "location":
			newStage = detectors.NewLocationStage()
		case "location_check":
			newStage = detectors.NewLocationCheckStage()
		case "comprehensive_tls":
			newStage = detectors.NewComprehensiveTLSStage()
		case "hot_website":
			newStage = detectors.NewHotWebsiteStage()
		}
		if newStage != nil {
			p.stages = append(p.stages, newStage)
			sort.Slice(p.stages, func(i, j int) bool {
				return p.stages[i].Priority() < p.stages[j].Priority()
			})
		}
	} else if !enabled && has {
		var newStages []types.DetectionStage
		for _, stage := range p.stages {
			if stage.Name() != name {
				newStages = append(newStages, stage)
			}
		}
		p.stages = newStages
	}
}

// ExecuteWithTargetIP 执行检测流水线 (支持可选显式指定测试 IP)
func (p *Pipeline) ExecuteWithTargetIP(ctx context.Context, domain string, targetIP string) (*types.DetectionResult, error) {
	startTime := time.Now()

	// 创建流水线上下文
	pipelineCtx := &types.PipelineContext{
		Domain:      domain,
		TargetIP:    targetIP,
		StartTime:   startTime,
		Result:      &types.DetectionResult{Domain: domain, StartTime: startTime},
		Connections: p.connections, // 传递连接管理器给检测器
		Cache:       nil,           // 缓存管理器已移除
		Config:      p.config,
		Context:     ctx, // 传递原始context
		EarlyExit:   false,
	}

	// 按优先级顺序执行检测阶段
	p.executeStages(ctx, pipelineCtx)

	// 计算总耗时
	pipelineCtx.Result.Duration = time.Since(startTime)

	// 评估适合性
	p.evaluateSuitability(pipelineCtx.Result)

	return pipelineCtx.Result, nil
}

// Execute 执行检测流水线
func (p *Pipeline) Execute(ctx context.Context, domain string) (*types.DetectionResult, error) {
	return p.ExecuteWithTargetIP(ctx, domain, "")
}

// executeStages 按优先级顺序严格执行各检测阶段（确定性且无数据竞争）
func (p *Pipeline) executeStages(ctx context.Context, pipelineCtx *types.PipelineContext) {
	p.mu.RLock()
	stages := make([]types.DetectionStage, len(p.stages))
	copy(stages, p.stages)
	earlyExit := p.earlyExit
	p.mu.RUnlock()

	for _, stage := range stages {
		select {
		case <-ctx.Done():
			pipelineCtx.Result.Error = ctx.Err()
			return
		default:
		}

		// 单阶段执行与 panic 防护
		func() {
			defer func() {
				if r := recover(); r != nil {
					pipelineCtx.Result.Error = fmt.Errorf("检测阶段 %s panic: %v", stage.Name(), r)
				}
			}()

			if err := stage.Execute(pipelineCtx); err != nil {
				pipelineCtx.Result.Error = err
				if stage.CanEarlyExit() {
					pipelineCtx.EarlyExit = true
				}
			}
		}()

		// 检查是否触发早期退出
		if earlyExit && stage.CanEarlyExit() && pipelineCtx.EarlyExit {
			pipelineCtx.Result.EarlyExit = true
			return
		}
	}
}

// evaluateSuitability 评估硬性技术与协议基线
// 注意：本方法仅检验该目标是否具备作为 REALITY 伪装协议的技术硬性底线（TLS 1.3 / X25519 / 合法证书 / 存活网络）
// 一切主观偏好（CDN、热门大站、默认页面、特定状态码、握手延迟阈值等）均不在此阻断，
// 而是作为元数据特征打标入库，由查询过滤（FilterTarget / QueryTargets）在消费侧决定。
func (p *Pipeline) evaluateSuitability(result *types.DetectionResult) {
	filter := types.FilterConfig{}
	if p.config != nil {
		filter = p.config.GetFilter()
	}

	// 检查 GFW 静态黑名单 (仅当启用了 check_gfw 时拦截)
	if filter.CheckGFW && result.Blocked != nil && result.Blocked.IsBlocked {
		result.Suitable = false
		result.Error = fmt.Errorf("域名被墙")
		return
	}

	// 检查国内网站 (仅当启用了 require_no_cn 时拦截，海外回国场景可放行)
	if filter.RequireNoCN && result.Location != nil && result.Location.IsDomestic {
		result.Suitable = false
		result.Error = fmt.Errorf("国内网站")
		return
	}

	if result.Network != nil && !result.Network.Accessible {
		result.Suitable = false
		result.Error = fmt.Errorf("网络不可达")
		result.StatusCodeCategory = types.StatusCodeCategoryNetwork
		return
	}

	// 维护状态码分类元数据（供资产特征记录与后续查询过滤使用，不作为落库硬性阻断项）
	if result.Network != nil && result.Network.Accessible {
		statusCode := result.Network.StatusCode
		isExcluded := false

		if len(filter.ExcludeStatus) > 0 {
			for _, s := range filter.ExcludeStatus {
				if s == statusCode {
					isExcluded = true
					break
				}
			}
		} else {
			isExcluded = types.IsStatusCodeExcluded(statusCode)
		}

		if isExcluded {
			result.StatusCodeCategory = types.StatusCodeCategoryExcluded
		} else {
			result.StatusCodeCategory = types.StatusCodeCategorySafe
		}
	}

	if result.TLS != nil {
		if !result.TLS.SupportsTLS13 {
			result.Suitable = false
			result.Error = fmt.Errorf("不支持TLS 1.3")
			return
		}
		if !result.TLS.SupportsX25519 {
			result.Suitable = false
			result.Error = fmt.Errorf("不支持X25519密钥交换")
			return
		}
		if !result.TLS.SupportsHTTP2 {
			result.Suitable = false
			result.Error = fmt.Errorf("不支持HTTP/2")
			return
		}
	}

	if result.Certificate != nil {
		if !result.Certificate.Valid {
			result.Suitable = false
			result.Error = fmt.Errorf("证书无效")
			return
		}
		// 只有真正过期的证书才标记为不适合（天数小于等于0）
		if result.Certificate.DaysUntilExpiry <= 0 {
			result.Suitable = false
			result.Error = fmt.Errorf("证书已过期（%d天）", result.Certificate.DaysUntilExpiry)
			return
		}
	}

	if result.SNI != nil && (!result.SNI.SupportsSNI || !result.SNI.SNIMatch) {
		result.Suitable = false
		result.Error = fmt.Errorf("SNI不匹配")
		return
	}

	// 所有硬性条件都符合
	result.Suitable = true
	result.HardRequirementsMet = true
}

// SetEarlyExit 设置是否早期退出
func (p *Pipeline) SetEarlyExit(earlyExit bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.earlyExit = earlyExit
}

// GetStages 获取当前所有阶段副本
func (p *Pipeline) GetStages() []types.DetectionStage {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]types.DetectionStage, len(p.stages))
	copy(res, p.stages)
	return res
}

// AddStage 添加检测阶段
func (p *Pipeline) AddStage(stage types.DetectionStage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stages = append(p.stages, stage)
	sort.Slice(p.stages, func(i, j int) bool {
		return p.stages[i].Priority() < p.stages[j].Priority()
	})
}

// RemoveStage 移除检测阶段
func (p *Pipeline) RemoveStage(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var newStages []types.DetectionStage
	for _, stage := range p.stages {
		if stage.Name() != name {
			newStages = append(newStages, stage)
		}
	}
	p.stages = newStages
}

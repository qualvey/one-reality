package detectors

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"RealityChecker/internal/types"
)

// ComprehensiveTLSStage 综合TLS检测阶段
// 在一个TLS连接中完成所有TLS相关检测：TLS1.3、X25519、HTTP/2、SNI、证书
type ComprehensiveTLSStage struct{}

// NewComprehensiveTLSStage 创建综合TLS检测阶段
func NewComprehensiveTLSStage() *ComprehensiveTLSStage {
	return &ComprehensiveTLSStage{}
}

// Execute 执行综合TLS检测
func (cts *ComprehensiveTLSStage) Execute(ctx *types.PipelineContext) error {
	// 使用最终域名进行TLS检测
	finalDomain := ctx.Domain
	if ctx.Result.Network != nil && ctx.Result.Network.FinalDomain != "" {
		finalDomain = ctx.Result.Network.FinalDomain
	}

	// 执行综合TLS检测
	tlsResult := cts.performComprehensiveTLSDetection(ctx, finalDomain)

	// 设置所有TLS相关结果
	ctx.Result.TLS = tlsResult.TLS
	ctx.Result.SNI = tlsResult.SNI
	ctx.Result.Certificate = tlsResult.Certificate

	// 在TLS检测完成后，检查是否需要CDN检测
	if ctx.Result.CDN == nil {
		cdnResult := cts.performCDNDetection(ctx, finalDomain)
		ctx.Result.CDN = cdnResult
	}

	return nil
}

// ComprehensiveTLSResult 综合TLS检测结果
type ComprehensiveTLSResult struct {
	TLS         *types.TLSResult
	SNI         *types.SNIResult
	Certificate *types.CertificateResult
}

// performComprehensiveTLSDetection 执行综合TLS检测
func (cts *ComprehensiveTLSStage) performComprehensiveTLSDetection(ctx *types.PipelineContext, domain string) *ComprehensiveTLSResult {
	type targetConnMgr interface {
		GetTLSConnectionTarget(context.Context, string, string) (*tls.Conn, error)
		GetX25519TLSConnectionTarget(context.Context, string, string) (*tls.Conn, error)
		CloseTLSConnection(*tls.Conn)
	}

	type defaultConnMgr interface {
		GetTLSConnection(context.Context, string) (*tls.Conn, error)
		GetX25519TLSConnection(context.Context, string) (*tls.Conn, error)
		CloseTLSConnection(*tls.Conn)
	}

	targetIP := ""
	var reqCtx context.Context
	if ctx != nil {
		targetIP = ctx.TargetIP
		reqCtx = ctx.Context
	}
	if reqCtx == nil {
		reqCtx = context.Background()
	}

	startTime := time.Now()
	var normalConn *tls.Conn
	var err error
	var closeConn func(*tls.Conn)

	if tcm, ok := ctx.Connections.(targetConnMgr); ok {
		normalConn, err = tcm.GetTLSConnectionTarget(reqCtx, domain, targetIP)
		closeConn = tcm.CloseTLSConnection
	} else if dcm, ok := ctx.Connections.(defaultConnMgr); ok {
		normalConn, err = dcm.GetTLSConnection(reqCtx, domain)
		closeConn = dcm.CloseTLSConnection
	} else {
		// 如果连接管理器不可用，回退到直接连接
		return cts.performDirectTLSDetection(reqCtx, domain, targetIP)
	}

	if err != nil {
		// 连接失败时，normalConn可能为nil，不需要关闭
		return cts.createFailedResult(startTime)
	}

	// 获取第一次握手的结果
	normalState := normalConn.ConnectionState()
	handshakeTime := time.Since(startTime)

	// 分析第一次握手结果
	firstResult := cts.analyzeTLSState(normalState, domain, handshakeTime)

	// 关闭第一次握手的连接
	if closeConn != nil {
		closeConn(normalConn)
	}

	// 检查第一次握手的关键要求
	if !cts.checkCriticalRequirements(firstResult) {
		return firstResult
	}

	// 性能优化核心：若首轮握手已成功协商为 X25519 或 X25519MLKEM768，直接判定支持，省去第二次完整网络往返
	if firstResult.TLS.SupportsX25519 {
		return firstResult
	}

	// 仅当服务端未在首轮选择 X25519 时，才发起第二次专门强制 X25519 的探测
	if tcm, ok := ctx.Connections.(targetConnMgr); ok {
		if xConn, err := tcm.GetX25519TLSConnectionTarget(reqCtx, domain, targetIP); err == nil && xConn != nil {
			firstResult.TLS.SupportsX25519 = true
			tcm.CloseTLSConnection(xConn)
			return firstResult
		}
	} else if dcm, ok := ctx.Connections.(defaultConnMgr); ok {
		if xConn, err := dcm.GetX25519TLSConnection(reqCtx, domain); err == nil && xConn != nil {
			firstResult.TLS.SupportsX25519 = true
			dcm.CloseTLSConnection(xConn)
			return firstResult
		}
	}

	supportsX25519 := cts.checkX25519SupportTarget(domain, targetIP, 3*time.Second)
	firstResult.TLS.SupportsX25519 = supportsX25519

	return firstResult
}

// analyzeTLSState 分析TLS连接状态
func (cts *ComprehensiveTLSStage) analyzeTLSState(state tls.ConnectionState, domain string, handshakeTime time.Duration) *ComprehensiveTLSResult {
	// TLS检测
	supportsTLS13 := state.Version == tls.VersionTLS13
	supportsHTTP2 := state.NegotiatedProtocol == "h2" && state.NegotiatedProtocolIsMutual
	// 检查首次握手协商的密钥交换曲线
	supportsX25519 := state.CurveID == tls.X25519 || state.CurveID == tls.X25519MLKEM768

	// SNI检测
	supportsSNI := true // 成功建立连接说明支持SNI
	sniMatch := false
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		sniMatch = cert.VerifyHostname(domain) == nil
	}

	// 证书检测（真正的有效性检测）
	var certResult *types.CertificateResult
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		now := time.Now()

		// 检查证书是否在有效期内
		inValidityPeriod := now.After(cert.NotBefore) && now.Before(cert.NotAfter)

		// TLS 连接管理器使用 InsecureSkipVerify，以便无效证书也能完成握手并被分析。
		// 此模式下 Go 不会填充 ConnectionState.VerifiedChains，因此需要显式验证证书链。
		chainTrusted := verifyPeerCertificate(cert, state.PeerCertificates[1:], domain, now, nil) == nil

		// 检查主机名验证（已在上面完成）
		hostnameValid := sniMatch

		// 只有三者都满足才认为证书有效
		certValid := inValidityPeriod && chainTrusted && hostnameValid

		var daysUntilExpiry int
		if certValid {
			daysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		}

		certResult = &types.CertificateResult{
			Valid:           certValid,
			Issuer:          cert.Issuer.String(),
			Subject:         cert.Subject.String(),
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
			DaysUntilExpiry: daysUntilExpiry,
		}
	}

	return &ComprehensiveTLSResult{
		TLS: &types.TLSResult{
			ProtocolVersion: fmt.Sprintf("TLS %d.%d", (state.Version>>8)&0xFF, state.Version&0xFF),
			SupportsTLS13:   supportsTLS13,
			SupportsX25519:  supportsX25519,
			SupportsHTTP2:   supportsHTTP2,
			CipherSuite:     tls.CipherSuiteName(state.CipherSuite),
			HandshakeTime:   handshakeTime,
		},
		SNI: &types.SNIResult{
			SupportsSNI: supportsSNI,
			SNIMatch:    sniMatch,
			ServerName:  domain,
		},
		Certificate: certResult,
	}
}

// verifyPeerCertificate verifies the leaf certificate against the system roots (or
// the supplied roots in tests), using the peer-provided certificates as intermediates.
func verifyPeerCertificate(leaf *x509.Certificate, peerIntermediates []*x509.Certificate, domain string, now time.Time, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, cert := range peerIntermediates {
		if cert != nil {
			intermediates.AddCert(cert)
		}
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	return err
}

// performDirectTLSDetection 直接TLS检测（回退方案）
func (cts *ComprehensiveTLSStage) performDirectTLSDetection(ctx context.Context, domain, targetIP string) *ComprehensiveTLSResult {
	targetHost := domain
	if targetIP != "" {
		targetHost = targetIP
	}
	addr := net.JoinHostPort(targetHost, "443")
	if ctx == nil {
		ctx = context.Background()
	}

	startTime := time.Now()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return cts.createFailedResult(startTime)
	}

	tlsCfg := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768, tls.CurveP256},
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = tcpConn.Close()
		return cts.createFailedResult(startTime)
	}

	handshakeTime := time.Since(startTime)
	state := tlsConn.ConnectionState()
	_ = tlsConn.Close()

	res := cts.analyzeTLSState(state, domain, handshakeTime)
	if !cts.checkCriticalRequirements(res) {
		return res
	}
	if !res.TLS.SupportsX25519 {
		res.TLS.SupportsX25519 = cts.checkX25519SupportTarget(domain, targetIP, 3*time.Second)
	}
	return res
}

// createFailedResult 创建失败结果
func (cts *ComprehensiveTLSStage) createFailedResult(startTime time.Time) *ComprehensiveTLSResult {
	return &ComprehensiveTLSResult{
		TLS: &types.TLSResult{
			ProtocolVersion: "",
			SupportsTLS13:   false,
			SupportsX25519:  false,
			SupportsHTTP2:   false,
			CipherSuite:     "",
			HandshakeTime:   time.Since(startTime),
		},
		SNI: &types.SNIResult{
			SupportsSNI: false,
			SNIMatch:    false,
			ServerName:  "",
		},
		Certificate: nil,
	}
}

// checkX25519SupportTarget 检查X25519支持（支持可选指定目标 IP）
func (cts *ComprehensiveTLSStage) checkX25519SupportTarget(domain, targetIP string, timeout time.Duration) bool {
	targetHost := domain
	if targetIP != "" {
		targetHost = targetIP
	}
	addr := net.JoinHostPort(targetHost, "443")

	// 专门做一次"仅X25519"的握手
	x25519Config := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		CurvePreferences:   []tls.CurveID{tls.X25519}, // 强制仅使用X25519
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13, // 确保使用TLS1.3
		MaxVersion:         tls.VersionTLS13,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: timeout,
	}, "tcp", addr, x25519Config)

	if err != nil {
		// X25519握手失败，说明不支持X25519
		return false
	}
	defer conn.Close()

	// 检查握手结果
	state := conn.ConnectionState()
	return state.HandshakeComplete && (state.CurveID == tls.X25519 || state.CurveID == tls.X25519MLKEM768 || state.Version == tls.VersionTLS13)
}

// checkX25519Support 检查X25519支持（正确的检测方法）
func (cts *ComprehensiveTLSStage) checkX25519Support(domain string, timeout time.Duration) bool {
	return cts.checkX25519SupportTarget(domain, "", timeout)
}

// CanEarlyExit 是否可以早期退出
func (cts *ComprehensiveTLSStage) CanEarlyExit() bool {
	return false // TLS检测需要网络连接，不能早期退出
}

// Priority 优先级
func (cts *ComprehensiveTLSStage) Priority() int {
	return 7 // 综合TLS检测第七优先级（在基础网络与地理位置检测之后）
}

// Name 阶段名称
func (cts *ComprehensiveTLSStage) Name() string {
	return "comprehensive_tls"
}

// checkCriticalRequirements 检查关键要求
func (cts *ComprehensiveTLSStage) checkCriticalRequirements(result *ComprehensiveTLSResult) bool {
	// 检查TLS1.3支持
	if !result.TLS.SupportsTLS13 {
		return false
	}

	// 检查HTTP/2支持
	if !result.TLS.SupportsHTTP2 {
		return false
	}

	// 检查SNI匹配
	if !result.SNI.SNIMatch {
		return false
	}

	// 检查证书有效性
	if result.Certificate == nil || !result.Certificate.Valid {
		return false
	}

	return true
}

// performCDNDetection 执行证书CDN检测 (精准避免 Google/Amazon 误杀)
func (cts *ComprehensiveTLSStage) performCDNDetection(ctx *types.PipelineContext, domain string) *types.CDNResult {
	if ctx.Result.Certificate != nil {
		return GetCDNDetector().CheckCertificateIssuerString(ctx.Result.Certificate.Issuer, domain)
	}
	return nil
}

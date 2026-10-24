package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/data"
	"RealityChecker/internal/logger"
	"RealityChecker/internal/network"

	"github.com/oschwald/geoip2-golang"
)

type Scanner struct {
	geoReader   *geoip2.Reader
	proxyURL    string
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewScanner(proxyURL ...string) *Scanner {
	s := &Scanner{}
	if len(proxyURL) > 0 && strings.TrimSpace(proxyURL[0]) != "" {
		s.SetProxy(proxyURL[0])
	}
	if r, err := data.OpenGeoIPReader("data/Country.mmdb", "Country.mmdb"); err == nil {
		s.geoReader = r
	}
	return s
}

func (s *Scanner) SetProxy(proxyURL string) {
	s.proxyURL = strings.TrimSpace(proxyURL)
	if s.proxyURL != "" {
		if dc, err := network.MakeDialContext(s.proxyURL, 3*time.Second); err == nil {
			s.dialContext = dc
		}
	} else {
		s.dialContext = nil
	}
}

func (s *Scanner) Close() {
	if s.geoReader != nil {
		s.geoReader.Close()
	}
}

func (s *Scanner) getGeo(ip net.IP) string {
	if s.geoReader == nil || ip == nil {
		return "N/A"
	}
	country, err := s.geoReader.Country(ip)
	if err != nil || country.Country.IsoCode == "" {
		return "N/A"
	}
	return country.Country.IsoCode
}

// ExtractCertDomains 从证书中提取所有合法、去重后的公网真实域名列表（优先 SAN 具体域名，随后规范化通配符，回退 CommonName）
func ExtractCertDomains(leaf *x509.Certificate) []string {
	if leaf == nil {
		return nil
	}

	seen := make(map[string]bool)
	var specificDomains []string
	var wildcardDomains []string

	// 第一阶段：提取所有具体、非通配符的合法公网域名
	collectSpecific := func(raw string) {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if raw == "" || strings.HasPrefix(raw, "*.") || strings.Contains(raw, "*") {
			return
		}
		if IsValidPublicDomain(raw) && !seen[raw] {
			seen[raw] = true
			specificDomains = append(specificDomains, raw)
		}
	}

	for _, name := range leaf.DNSNames {
		collectSpecific(name)
	}
	collectSpecific(leaf.Subject.CommonName)

	// 第二阶段：提取通配符域名并规范化为主域名
	collectWildcard := func(raw string) {
		raw = strings.TrimSpace(strings.ToLower(raw))
		if !strings.HasPrefix(raw, "*.") || len(raw) <= 2 {
			return
		}
		cleaned := strings.TrimPrefix(raw, "*.")
		if cleaned != "" && !strings.Contains(cleaned, "*") && IsValidPublicDomain(cleaned) {
			if !seen[cleaned] {
				seen[cleaned] = true
				wildcardDomains = append(wildcardDomains, cleaned)
			}
		}
	}

	for _, name := range leaf.DNSNames {
		collectWildcard(name)
	}
	collectWildcard(leaf.Subject.CommonName)

	return append(specificDomains, wildcardDomains...)
}

// ExtractCertDomain 从证书中智能提取最适合的首选真实公网域名
func ExtractCertDomain(leaf *x509.Certificate) string {
	domains := ExtractCertDomains(leaf)
	if len(domains) > 0 {
		return domains[0]
	}
	return ""
}

// IsValidPublicDomain 检查提取出的域名是否为合法的公网 FQDN（过滤 localhost、纯 IP、单段主机名、内网/保留后缀）
func IsValidPublicDomain(domain string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" || domain == "localhost" {
		return false
	}
	// 排除纯 IP 地址
	if net.ParseIP(domain) != nil {
		return false
	}
	// 必须包含至少一个点，且点不能在首尾，也不能包含连续点
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return false
	}
	// 排除包含非法字符或空字符
	if strings.ContainsAny(domain, " \t\r\n*:/\\#@!") {
		return false
	}
	// 排除常见本地和保留后缀
	invalidSuffixes := []string{
		".local", ".lan", ".internal", ".home", ".corp",
		".arpa", ".test", ".example", ".invalid", ".localhost",
	}
	for _, suffix := range invalidSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return false
		}
	}
	return true
}

// VerifyPublicCACert 验证证书是否由受信任的公网根 CA 颁发且在有效期内（排除自签名证书、私有证书与过期证书）
func VerifyPublicCACert(leaf *x509.Certificate, intermediates []*x509.Certificate) error {
	if leaf == nil {
		return errors.New("证书为空")
	}

	// 检查有效期
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("证书尚未生效 (生效时间: %s)", leaf.NotBefore.Format("2006-01-02"))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("证书已过期 (过期时间: %s)", leaf.NotAfter.Format("2006-01-02"))
	}

	// 排除自签名证书 (当 Issuer 等同于 Subject 时判定为自签)
	if leaf.Issuer.String() == leaf.Subject.String() {
		return errors.New("自签名证书 (Self-signed)")
	}

	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
		CurrentTime:   now,
	}
	for _, cert := range intermediates {
		opts.Intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("非受信任的公共CA签发: %w", err)
	}

	return nil
}

// isLocalResourceExhaustion 判定是否为本地套接字/缓冲区耗尽错误
func isLocalResourceExhaustion(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no buffer space available") ||
		strings.Contains(s, "wsaenobufs") ||
		strings.Contains(s, "wsaeaddrinuse") ||
		strings.Contains(s, "address already in use") ||
		strings.Contains(s, "too many open files")
}

// isTransientNetError 判定是否为偶发网络重置或连接中断（适宜单次快速重试）
func isTransientNetError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "wsaconnreset") ||
		strings.Contains(s, "eof")
}

func (s *Scanner) scanTLSSingleWithProbe(ctx context.Context, host Host, port int, timeout int) (*ScanResult, bool, *ProbeResult) {
	probe := &ProbeResult{
		IP:   host.IP.String(),
		Port: port,
	}

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	var conn net.Conn
	var err error

	// 应对本地套接字/端口耗尽做最多 3 次退避重试
	for attempt := 0; attempt < 3; attempt++ {
		if s.dialContext != nil {
			conn, err = s.dialContext(ctx, "tcp", hostPort)
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", hostPort)
		}
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			probe.Error = ctx.Err()
			probe.FailureReason = "扫描已取消"
			return nil, false, probe
		}
		if isLocalResourceExhaustion(err) {
			select {
			case <-ctx.Done():
				probe.Error = ctx.Err()
				probe.FailureReason = "扫描已取消"
				return nil, false, probe
			case <-time.After(time.Duration(40*(attempt+1)) * time.Millisecond):
				continue
			}
		}
		break
	}

	if err != nil || conn == nil {
		probe.Error = err
		if err != nil {
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
				probe.FailureReason = "连接超时"
			} else if strings.Contains(errStr, "refused") {
				probe.FailureReason = "端口未开放 (连接被拒绝)"
			} else if strings.Contains(errStr, "no route") || strings.Contains(errStr, "unreachable") {
				probe.FailureReason = "网络不可达"
			} else {
				probe.FailureReason = "TCP连接失败: " + err.Error()
			}
		} else {
			probe.FailureReason = "TCP连接失败"
		}
		return nil, isTransientNetError(err), probe
	}

	// 核心修复：开启 SetLinger(0) 主动发送 RST 关闭连接，让操作系统内核立即回收端口，根除 TIME_WAIT 端口耗尽
	defer func() {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
	}
	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}

	c := tls.Client(conn, tlsCfg)
	if err := c.HandshakeContext(ctx); err != nil {
		probe.Error = err
		probe.FailureReason = "TLS握手失败: " + err.Error()
		return nil, isTransientNetError(err), probe
	}

	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		probe.FailureReason = "服务端未提供有效TLS证书"
		return nil, false, probe
	}

	leaf := state.PeerCertificates[0]
	domains := ExtractCertDomains(leaf)
	if len(domains) == 0 {
		probe.FailureReason = "证书未包含有效公网域名 (SAN/CN为空、非法或内网域名)"
		return nil, false, probe
	}

	primaryDomain := domains[0]

	if err := VerifyPublicCACert(leaf, state.PeerCertificates[1:]); err != nil {
		probe.FailureReason = "证书有效性校验失败: " + err.Error()
		return nil, false, probe
	}

	alpn := state.NegotiatedProtocol
	if state.Version != tls.VersionTLS13 || alpn != "h2" {
		probe.FailureReason = fmt.Sprintf("非目标协议 (版本: %s, ALPN: %s)", tls.VersionName(state.Version), alpn)
		return nil, false, probe
	}

	issuers := strings.Join(leaf.Issuer.Organization, " | ")
	length := 0
	for _, cert := range state.PeerCertificates {
		length += len(cert.Raw)
	}

	geoCode := s.getGeo(host.IP)

	res := &ScanResult{
		IP:            host.IP.String(),
		Origin:        host.Origin,
		TLSVersion:    tls.VersionName(state.Version),
		ALPN:          alpn,
		Curve:         state.CurveID.String(),
		CertLength:    strconv.Itoa(length) + "(certs count: " + strconv.Itoa(len(state.PeerCertificates)) + ")",
		CertSignature: leaf.SignatureAlgorithm.String(),
		CertPublicKey: leaf.PublicKeyAlgorithm.String(),
		CertDomain:    primaryDomain,
		CertDomains:   domains,
		CertIssuer:    issuers,
		GeoCode:       geoCode,
	}

	probe.Success = true
	probe.Result = res
	return res, false, probe
}

func (s *Scanner) scanTLSSingle(ctx context.Context, host Host, port int, timeout int) (*ScanResult, bool) {
	res, retry, _ := s.scanTLSSingleWithProbe(ctx, host, port, timeout)
	return res, retry
}

// ScanTLSProbe 检测单主机/IP 并返回详细探测记录
func (s *Scanner) ScanTLSProbe(ctx context.Context, host Host, port int, timeout int, enableIPv6 bool) (*ScanResult, *ProbeResult) {
	select {
	case <-ctx.Done():
		return nil, &ProbeResult{IP: host.IP.String(), Port: port, FailureReason: "扫描已取消"}
	default:
	}

	if host.IP == nil {
		ip, err := LookupIP(host.Origin, enableIPv6)
		if err != nil {
			return nil, &ProbeResult{IP: host.Origin, Port: port, Error: err, FailureReason: "DNS解析失败: " + err.Error()}
		}
		host.IP = ip
	}

	res, shouldRetry, probe := s.scanTLSSingleWithProbe(ctx, host, port, timeout)
	if res == nil && shouldRetry && ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return nil, probe
		case <-time.After(30 * time.Millisecond):
		}
		res, _, probe = s.scanTLSSingleWithProbe(ctx, host, port, timeout)
	}

	return res, probe
}

// ScanTLS 检测单主机/IP 是否支持 TLS1.3 + h2 并提取域名
func (s *Scanner) ScanTLS(ctx context.Context, host Host, port int, timeout int, enableIPv6 bool) *ScanResult {
	res, _ := s.ScanTLSProbe(ctx, host, port, timeout, enableIPv6)
	return res
}

// RateLimiter 扫描流控接口 (可选)
type RateLimiter interface {
	Acquire(ctx context.Context) error
	Release()
	ReportProbe(duration time.Duration, isTimeout bool, isSuccess bool)
}

// ScanCIDRStream 执行并发扫描并把结果通过 Channel 传出 (支持从 startIP 断点处继续)
func (s *Scanner) ScanCIDRStream(ctx context.Context, cidrStr string, startIP string, port int, threads int, timeout int, enableIPv6 bool, outChan chan<- *ScanResult,
	onProgress func(n int, currentIP string),
) {
	s.ScanCIDRStreamAdaptive(ctx, cidrStr, startIP, port, threads, timeout, enableIPv6, nil, outChan, onProgress, nil)
}

// ScanCIDRStreamWithProbe 执行并发扫描，同时向 onProbe 回调发送每个 IP 的探活详情记录
func (s *Scanner) ScanCIDRStreamWithProbe(ctx context.Context, cidrStr string, startIP string, port int, threads int, timeout int, enableIPv6 bool, outChan chan<- *ScanResult,
	onProgress func(n int, currentIP string),
	onProbe func(probe *ProbeResult),
) {
	s.ScanCIDRStreamAdaptive(ctx, cidrStr, startIP, port, threads, timeout, enableIPv6, nil, outChan, onProgress, onProbe)
}

// ScanCIDRStreamAdaptive 执行并发扫描，支持自适应 RateLimiter 动态调谐、断点续扫与探活明细回调
func (s *Scanner) ScanCIDRStreamAdaptive(ctx context.Context, cidrStr string, startIP string, port int, threads int, timeout int, enableIPv6 bool,
	limiter RateLimiter,
	outChan chan<- *ScanResult,
	onProgress func(n int, currentIP string),
	onProbe func(probe *ProbeResult),
) {
	hostChan := IterateCIDR(ctx, cidrStr, startIP, enableIPv6)

	if threads <= 0 {
		threads = 50
	}

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for host := range hostChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if logger.IsDebug() {
					logger.Debug("正在尝试 TLS1.3/h2 握手 IP: %s:%d", host.IP.String(), port)
				}

				if limiter != nil {
					if err := limiter.Acquire(ctx); err != nil {
						return
					}
				}

				probeStart := time.Now()
				res, probe := s.ScanTLSProbe(ctx, host, port, timeout, enableIPv6)
				probeDuration := time.Since(probeStart)

				if limiter != nil {
					limiter.Release()
					isTimeout := false
					isSuccess := false
					if probe != nil {
						isSuccess = probe.Success
						if !probe.Success && strings.Contains(probe.FailureReason, "超时") {
							isTimeout = true
						}
					}
					limiter.ReportProbe(probeDuration, isTimeout, isSuccess)
				}

				// 无论成功还是失败，单 IP 探测结束立刻触发步进并回传当前探测的 IP
				if onProgress != nil {
					onProgress(1, host.IP.String())
				}
				if onProbe != nil && probe != nil {
					onProbe(probe)
				}
				if res != nil {
					if logger.IsDebug() {
						logger.Debug("IP: %s 握手成功! 提取证书CN: %s, ALPN: %s, 加密套件: %s", host.IP.String(), res.CertDomain, res.ALPN, res.Curve)
					}
					select {
					case outChan <- res:
					case <-ctx.Done():
						return
					}
				} else if logger.IsDebug() {
					logger.Debug("IP: %s 握手失败/未响应/非 TLS1.3+h2", host.IP.String())
				}
			}
		}()
	}

	wg.Wait()
}

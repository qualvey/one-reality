package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/logger"

	"github.com/oschwald/geoip2-golang"
)

type Scanner struct {
	geoReader *geoip2.Reader
}

func NewScanner() *Scanner {
	s := &Scanner{}
	paths := []string{"data/Country.mmdb", "Country.mmdb"}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			if r, err := geoip2.Open(p); err == nil {
				s.geoReader = r
				break
			}
		}
	}
	return s
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

// ExtractCertDomain 从证书中智能提取最适合的真实域名（优先 SAN/DNSNames，回退 CommonName，自动清洗通配符）
func ExtractCertDomain(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}

	// 1. 优先在 DNSNames (SAN) 中寻找具体非通配符域名
	for _, name := range leaf.DNSNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !strings.HasPrefix(name, "*.") && !strings.Contains(name, "*") {
			return strings.ToLower(name)
		}
	}

	// 2. 如果 DNSNames 只有通配符域名（例如 *.example.com），去除 "*." 规范化为主域名
	for _, name := range leaf.DNSNames {
		name = strings.TrimSpace(name)
		if strings.HasPrefix(name, "*.") && len(name) > 2 {
			cleaned := strings.TrimPrefix(name, "*.")
			if cleaned != "" && !strings.Contains(cleaned, "*") {
				return strings.ToLower(cleaned)
			}
		}
	}

	// 3. DNSNames 为空或无有效记录时，回退检查 CommonName
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn != "" {
		if strings.HasPrefix(cn, "*.") && len(cn) > 2 {
			cn = strings.TrimPrefix(cn, "*.")
		}
		if cn != "" && !strings.Contains(cn, "*") {
			return strings.ToLower(cn)
		}
	}

	return ""
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

func (s *Scanner) scanTLSSingle(ctx context.Context, host Host, port int, timeout int) (*ScanResult, bool) {
	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	var conn net.Conn
	var err error

	// 应对本地套接字/端口耗尽做最多 3 次退避重试
	for attempt := 0; attempt < 3; attempt++ {
		conn, err = dialer.DialContext(ctx, "tcp", hostPort)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil, false
		}
		if isLocalResourceExhaustion(err) {
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(time.Duration(40*(attempt+1)) * time.Millisecond):
				continue
			}
		}
		break
	}

	if err != nil || conn == nil {
		return nil, isTransientNetError(err)
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
		return nil, isTransientNetError(err)
	}

	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, false
	}

	leaf := state.PeerCertificates[0]
	domain := ExtractCertDomain(leaf)
	if len(domain) == 0 {
		return nil, false
	}

	alpn := state.NegotiatedProtocol
	if state.Version != tls.VersionTLS13 || alpn != "h2" {
		return nil, false
	}

	issuers := strings.Join(leaf.Issuer.Organization, " | ")
	length := 0
	for _, cert := range state.PeerCertificates {
		length += len(cert.Raw)
	}

	geoCode := s.getGeo(host.IP)

	return &ScanResult{
		IP:            host.IP.String(),
		Origin:        host.Origin,
		TLSVersion:    tls.VersionName(state.Version),
		ALPN:          alpn,
		Curve:         state.CurveID.String(),
		CertLength:    strconv.Itoa(length) + "(certs count: " + strconv.Itoa(len(state.PeerCertificates)) + ")",
		CertSignature: leaf.SignatureAlgorithm.String(),
		CertPublicKey: leaf.PublicKeyAlgorithm.String(),
		CertDomain:    domain,
		CertIssuer:    issuers,
		GeoCode:       geoCode,
	}, false
}

// ScanTLS 检测单主机/IP 是否支持 TLS1.3 + h2 并提取域名
func (s *Scanner) ScanTLS(ctx context.Context, host Host, port int, timeout int, enableIPv6 bool) *ScanResult {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if host.IP == nil {
		ip, err := LookupIP(host.Origin, enableIPv6)
		if err != nil {
			return nil
		}
		host.IP = ip
	}

	res, shouldRetry := s.scanTLSSingle(ctx, host, port, timeout)
	if res == nil && shouldRetry && ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Millisecond):
		}
		res, _ = s.scanTLSSingle(ctx, host, port, timeout)
	}

	return res
}

// ScanCIDRStream 执行并发扫描并把结果通过 Channel 传出 (支持从 startIP 断点处继续)
func (s *Scanner) ScanCIDRStream(ctx context.Context, cidrStr string, startIP string, port int, threads int, timeout int, enableIPv6 bool, outChan chan<- *ScanResult,
	onProgress func(n int, currentIP string),
) {
	hostChan := IterateCIDR(ctx, cidrStr, startIP, enableIPv6)

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

				res := s.ScanTLS(ctx, host, port, timeout, enableIPv6)
				// 无论成功还是失败，单 IP 探测结束立刻触发步进并回传当前探测的 IP
				if onProgress != nil {
					onProgress(1, host.IP.String())
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

package scanner

import (
	"context"
	"crypto/tls"
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

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil
	}
	defer conn.Close()

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
		return nil
	}

	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	alpn := state.NegotiatedProtocol
	domain := state.PeerCertificates[0].Subject.CommonName
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	length := 0
	leaf := state.PeerCertificates[0]

	for _, cert := range state.PeerCertificates {
		length += len(cert.Raw)
		if len(cert.DNSNames) != 0 {
			leaf = cert
		}
	}

	// 只要符合 REALITY 基本硬性条件 TLS1.3 + h2
	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 {
		return nil
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
	}
}

// ScanCIDRStream 执行并发扫描并把结果通过 Channel 传出
func (s *Scanner) ScanCIDRStream(ctx context.Context, cidrStr string, port int, threads int, timeout int, enableIPv6 bool, outChan chan<- *ScanResult,
	onProgress func(n int, currentIP string),
) {
	hostChan := IterateCIDR(ctx, cidrStr, enableIPv6)

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
				// 2.【核心位置】无论成功还是失败，单 IP 探测结束立刻触发步进并回传当前探测的 IP
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

package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
)

// IterateCIDR 返回迭代 CIDR 或单个 IP/域名的 Host 通道 (支持从 startIP 断点处继续)
func IterateCIDR(ctx context.Context, cidrStr string, startIP string, enableIPv6 bool) <-chan Host {
	hostChan := make(chan Host, 100)
	go func() {
		defer close(hostChan)

		p, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			// 如果不是 CIDR，尝试单 IP 或 域名
			ip := net.ParseIP(cidrStr)
			if ip != nil {
				select {
				case hostChan <- Host{IP: ip, Origin: cidrStr, Type: HostTypeIP}:
				case <-ctx.Done():
				}
				return
			}
			if ValidateDomainName(cidrStr) {
				select {
				case hostChan <- Host{IP: nil, Origin: cidrStr, Type: HostTypeDomain}:
				case <-ctx.Done():
				}
				return
			}
			return
		}

		if !p.Addr().Is4() && !enableIPv6 {
			return
		}

		p = p.Masked()
		addr := p.Addr()

		// 如果指定了断点 startIP，从该 IP 的下一个 IP 开始遍历
		if startIP != "" {
			if startAddr, err := netip.ParseAddr(startIP); err == nil && p.Contains(startAddr) {
				addr = startAddr.Next()
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if !p.Contains(addr) {
				break
			}

			ip := net.ParseIP(addr.String())
			if ip != nil {
				select {
				case hostChan <- Host{IP: ip, Origin: cidrStr, Type: HostTypeCIDR}:
				case <-ctx.Done():
					return
				}
			}
			addr = addr.Next()
		}
	}()
	return hostChan
}

func ValidateDomainName(domain string) bool {
	r := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`)
	return r.MatchString(domain)
}

func LookupIP(addr string, enableIPv6 bool) (net.IP, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup: %w", err)
	}
	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil || enableIPv6 {
			arr = append(arr, ip)
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("no IP found")
	}
	return arr[0], nil
}

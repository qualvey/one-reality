package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// NormalizeProxyURL 规范化代理 URL 并校验协议
func NormalizeProxyURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	// 如果未指定协议前缀，默认补充 http://
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("解析代理地址失败: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
		return parsed, nil
	default:
		return nil, fmt.Errorf("不支持的代理协议: %s (仅支持 http, https, socks5, socks5h)", parsed.Scheme)
	}
}

// MakeDialContext 构建支持直连、SOCKS5 与 HTTP CONNECT 的上下文感应拨号函数
func MakeDialContext(proxyURL string, timeout time.Duration) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	u, err := NormalizeProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	baseDialer := &net.Dialer{
		Timeout: timeout,
	}

	// 直连模式
	if u == nil {
		return baseDialer.DialContext, nil
	}

	scheme := strings.ToLower(u.Scheme)

	// SOCKS5 代理
	if scheme == "socks5" || scheme == "socks5h" {
		socksDialer, err := proxy.FromURL(u, baseDialer)
		if err != nil {
			return nil, fmt.Errorf("初始化 SOCKS5 代理拨号器失败: %w", err)
		}

		if cd, ok := socksDialer.(proxy.ContextDialer); ok {
			return cd.DialContext, nil
		}

		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			type dialResult struct {
				conn net.Conn
				err  error
			}
			done := make(chan dialResult, 1)
			go func() {
				c, e := socksDialer.Dial(network, addr)
				done <- dialResult{conn: c, err: e}
			}()

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case res := <-done:
				return res.conn, res.err
			}
		}, nil
	}

	// HTTP / HTTPS CONNECT 隧道代理 (用于向代理发送 CONNECT 并直通目标 TCP)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		proxyHostPort := u.Host
		if !strings.Contains(proxyHostPort, ":") {
			if scheme == "https" {
				proxyHostPort = net.JoinHostPort(proxyHostPort, "443")
			} else {
				proxyHostPort = net.JoinHostPort(proxyHostPort, "80")
			}
		}

		var conn net.Conn
		var err error

		if scheme == "https" {
			tlsDialer := &tls.Dialer{
				NetDialer: baseDialer,
				Config: &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         u.Hostname(),
				},
			}
			conn, err = tlsDialer.DialContext(ctx, "tcp", proxyHostPort)
		} else {
			conn, err = baseDialer.DialContext(ctx, "tcp", proxyHostPort)
		}

		if err != nil {
			return nil, fmt.Errorf("连接代理服务器 %s 失败: %w", proxyHostPort, err)
		}

		// 构造 HTTP CONNECT 请求
		connectReq := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}

		if u.User != nil {
			username := u.User.Username()
			password, _ := u.User.Password()
			auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			connectReq.Header.Set("Proxy-Authorization", "Basic "+auth)
		}

		connectReq.Header.Set("Proxy-Connection", "Keep-Alive")
		connectReq.Header.Set("User-Agent", "RealityChecker/1.0")

		if err := connectReq.Write(conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("向代理发送 CONNECT 请求失败: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connectReq)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("读取代理 CONNECT 响应失败: %w", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("代理拒绝连接 (%s): HTTP %d %s", addr, resp.StatusCode, resp.Status)
		}

		return conn, nil
	}, nil
}

// MakeHTTPTransport 创建配置了代理的 http.Transport
func MakeHTTPTransport(proxyURL string, timeout time.Duration) (*http.Transport, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		TLSNextProto:      make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	u, err := NormalizeProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	if u != nil {
		tr.Proxy = http.ProxyURL(u)
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}

	dialContext, err := MakeDialContext(proxyURL, timeout)
	if err != nil {
		return nil, err
	}
	tr.DialContext = dialContext

	return tr, nil
}

// MakeHTTPClient 创建配置了代理与超时的 http.Client
func MakeHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	tr, err := MakeHTTPTransport(proxyURL, timeout)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

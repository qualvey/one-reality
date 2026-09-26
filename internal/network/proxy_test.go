package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNormalizeProxyURL(t *testing.T) {
	tests := []struct {
		input       string
		expectURL   string
		expectNil   bool
		expectError bool
	}{
		{"", "", true, false},
		{"   ", "", true, false},
		{"127.0.0.1:7890", "http://127.0.0.1:7890", false, false},
		{"http://127.0.0.1:7890", "http://127.0.0.1:7890", false, false},
		{"https://user:pass@127.0.0.1:8443", "https://user:pass@127.0.0.1:8443", false, false},
		{"socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080", false, false},
		{"socks5h://127.0.0.1:1080", "socks5h://127.0.0.1:1080", false, false},
		{"ftp://127.0.0.1:21", "", false, true},
		{"://invalid-url", "", false, true},
	}

	for _, tt := range tests {
		u, err := NormalizeProxyURL(tt.input)
		if tt.expectError {
			if err == nil {
				t.Errorf("NormalizeProxyURL(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeProxyURL(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if tt.expectNil {
			if u != nil {
				t.Errorf("NormalizeProxyURL(%q) expected nil, got %v", tt.input, u)
			}
			continue
		}
		if u.String() != tt.expectURL {
			t.Errorf("NormalizeProxyURL(%q) = %q, want %q", tt.input, u.String(), tt.expectURL)
		}
	}
}

func TestMakeHTTPClient_And_Transport(t *testing.T) {
	client, err := MakeHTTPClient("http://127.0.0.1:7890", 3*time.Second)
	if err != nil {
		t.Fatalf("MakeHTTPClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != 3*time.Second {
		t.Errorf("expected timeout 3s, got %v", client.Timeout)
	}

	// 测试空代理直连
	clientDirect, err := MakeHTTPClient("", 0)
	if err != nil {
		t.Fatalf("MakeHTTPClient(empty) failed: %v", err)
	}
	if clientDirect == nil {
		t.Fatal("expected non-nil clientDirect")
	}
}

func TestMakeDialContext_HTTP_Connect(t *testing.T) {
	// 启动一个简易本地测试 HTTP 代理服务
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock proxy listener: %v", err)
	}
	defer proxyListener.Close()

	// 启动一个目标 Echo 服务
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	// 目标服务：接受连接并返回 "HELLO_TARGET"
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HELLO_TARGET\n"))
	}()

	// 简易 Mock 代理：处理 CONNECT 并将流量桥接到目标
	go func() {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		defer clientConn.Close()

		req, err := http.ReadRequest(bufio.NewReader(clientConn))
		if err != nil {
			return
		}

		if req.Method == http.MethodConnect && req.Host == targetAddr {
			_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

			// 直连目标
			destConn, err := net.Dial("tcp", req.Host)
			if err != nil {
				return
			}
			defer destConn.Close()

			// 双向转发单次消息
			buf := make([]byte, 128)
			n, _ := destConn.Read(buf)
			_, _ = clientConn.Write(buf[:n])
		}
	}()

	proxyURL := fmt.Sprintf("http://%s", proxyListener.Addr().String())
	dialFunc, err := MakeDialContext(proxyURL, 3*time.Second)
	if err != nil {
		t.Fatalf("MakeDialContext failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialFunc(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial via mock proxy failed: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read from target failed: %v", err)
	}

	if !strings.Contains(line, "HELLO_TARGET") {
		t.Fatalf("expected HELLO_TARGET, got %q", line)
	}
}

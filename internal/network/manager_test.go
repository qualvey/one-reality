package network

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"RealityChecker/internal/types"
)

func TestConnectionManager_LifecycleAndStats(t *testing.T) {
	cfg := &types.Config{
		Network: types.NetworkConfig{
			Timeout: 1 * time.Second,
		},
	}

	cm := NewConnectionManager(cfg)
	if err := cm.Start(); err != nil {
		t.Fatalf("unexpected Start error: %v", err)
	}

	stats := cm.GetStats()
	if stats.ActiveConnections != 0 || stats.TotalConnections != 0 || stats.FailedConnections != 0 {
		t.Errorf("expected zero stats, got %+v", stats)
	}

	if err := cm.Stop(); err != nil {
		t.Fatalf("unexpected Stop error: %v", err)
	}
}

func TestConnectionManager_ContextCancellation(t *testing.T) {
	cfg := &types.Config{
		Network: types.NetworkConfig{
			Timeout: 5 * time.Second,
		},
	}
	cm := NewConnectionManager(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 即刻取消

	_, err := cm.GetHTTPConnection(ctx, "192.0.2.1") // 不可达的保留测试地址
	if err == nil {
		t.Errorf("expected canceled context error, got nil")
	}

	stats := cm.GetStats()
	if stats.FailedConnections != 1 {
		t.Errorf("expected FailedConnections to be 1, got %d", stats.FailedConnections)
	}
}

func TestConnectionManager_CloseConnection(t *testing.T) {
	cm := NewConnectionManager(nil)

	// 本地启动一个临时 listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	host, _, _ := net.SplitHostPort(addr)

	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
		}
	}()

	conn, err := cm.dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	cm.mu.Lock()
	cm.stats.ActiveConnections = 1
	cm.stats.TotalConnections = 1
	cm.mu.Unlock()

	cm.CloseConnection(conn)

	stats := cm.GetStats()
	if stats.ActiveConnections != 0 {
		t.Errorf("expected ActiveConnections to be 0 after CloseConnection, got %d", stats.ActiveConnections)
	}
	_ = host
}

func TestConnectionManager_ProxyDial(t *testing.T) {
	// 启动简易 mock proxy
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start proxy listener: %v", err)
	}
	defer proxyListener.Close()

	// 启动目标
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}
	defer targetListener.Close()

	targetPort := targetListener.Addr().(*net.TCPAddr).Port

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := proxyListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// 读取 CONNECT 请求
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			// 保持连接直到对端关闭
			_, _ = conn.Read(buf)
		}
	}()

	cfg := &types.Config{
		Proxy: types.ProxyConfig{
			URL:     "http://" + proxyListener.Addr().String(),
			Scanner: true,
		},
		Network: types.NetworkConfig{
			Timeout: 2 * time.Second,
		},
	}

	cm := NewConnectionManager(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := cm.dialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", targetPort)))
	if err != nil {
		t.Fatalf("dial via proxy failed: %v", err)
	}
	conn.Close()
	<-done
}


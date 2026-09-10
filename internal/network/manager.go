package network

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"RealityChecker/internal/types"
)

// ConnectionManager 高性能网络连接管理器
// 统一管理底层 TCP/TLS 拨号，支持 Context 快速取消、SetLinger(0) 立即释放端口防 TIME_WAIT，以及并发统计
type ConnectionManager struct {
	config *types.Config
	dialer *net.Dialer
	mu     sync.RWMutex
	stats  types.ConnectionStats
}

// NewConnectionManager 创建连接管理器
func NewConnectionManager(config *types.Config) *ConnectionManager {
	timeout := 3 * time.Second
	if config != nil && config.Network.Timeout > 0 {
		timeout = config.Network.Timeout
	}

	return &ConnectionManager{
		config: config,
		dialer: &net.Dialer{
			Timeout: timeout,
		},
		stats: types.ConnectionStats{
			ActiveConnections: 0,
			TotalConnections:  0,
			FailedConnections: 0,
		},
	}
}

// Start 启动连接管理器
func (cm *ConnectionManager) Start() error {
	return nil
}

// Stop 停止连接管理器
func (cm *ConnectionManager) Stop() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.stats.ActiveConnections = 0
	return nil
}

// GetHTTPConnection 获取 context 感知的 HTTP 连接
func (cm *ConnectionManager) GetHTTPConnection(ctx context.Context, domain string) (net.Conn, error) {
	hostPort := net.JoinHostPort(domain, "80")
	conn, err := cm.dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		cm.mu.Lock()
		cm.stats.FailedConnections++
		cm.mu.Unlock()
		return nil, err
	}

	cm.mu.Lock()
	cm.stats.TotalConnections++
	cm.stats.ActiveConnections++
	cm.mu.Unlock()
	return conn, nil
}

// GetTLSConnection 获取支持 Context 握手与优先 X25519 曲线的 TLS 连接
func (cm *ConnectionManager) GetTLSConnection(ctx context.Context, domain string) (*tls.Conn, error) {
	hostPort := net.JoinHostPort(domain, "443")
	tcpConn, err := cm.dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		cm.mu.Lock()
		cm.stats.FailedConnections++
		cm.mu.Unlock()
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true, // 允许自签/异常证书完成握手以供后续检测阶段分析
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768, tls.CurveP256},
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = tcpConn.Close()
		cm.mu.Lock()
		cm.stats.FailedConnections++
		cm.mu.Unlock()
		return nil, err
	}

	cm.mu.Lock()
	cm.stats.TotalConnections++
	cm.stats.ActiveConnections++
	cm.mu.Unlock()
	return tlsConn, nil
}

// GetX25519TLSConnection 获取强制仅 X25519 的 TLS 连接（用于复核探测）
func (cm *ConnectionManager) GetX25519TLSConnection(ctx context.Context, domain string) (*tls.Conn, error) {
	hostPort := net.JoinHostPort(domain, "443")
	tcpConn, err := cm.dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		cm.mu.Lock()
		cm.stats.FailedConnections++
		cm.mu.Unlock()
		return nil, err
	}

	tlsCfg := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(tcpConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if tc, ok := tcpConn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = tcpConn.Close()
		cm.mu.Lock()
		cm.stats.FailedConnections++
		cm.mu.Unlock()
		return nil, err
	}

	cm.mu.Lock()
	cm.stats.TotalConnections++
	cm.stats.ActiveConnections++
	cm.mu.Unlock()
	return tlsConn, nil
}

// CloseConnection 关闭普通连接并使用 SetLinger(0) 立即回收套接字
func (cm *ConnectionManager) CloseConnection(conn net.Conn) {
	if conn == nil {
		return
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()

	cm.mu.Lock()
	if cm.stats.ActiveConnections > 0 {
		cm.stats.ActiveConnections--
	}
	cm.mu.Unlock()
}

// CloseTLSConnection 关闭 TLS 连接并使用 SetLinger(0) 立即回收套接字
func (cm *ConnectionManager) CloseTLSConnection(conn *tls.Conn) {
	if conn == nil {
		return
	}
	if tcpConn, ok := conn.NetConn().(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()

	cm.mu.Lock()
	if cm.stats.ActiveConnections > 0 {
		cm.stats.ActiveConnections--
	}
	cm.mu.Unlock()
}

// GetStats 获取当前连接统计
func (cm *ConnectionManager) GetStats() *types.ConnectionStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return &types.ConnectionStats{
		ActiveConnections: cm.stats.ActiveConnections,
		TotalConnections:  cm.stats.TotalConnections,
		FailedConnections: cm.stats.FailedConnections,
	}
}

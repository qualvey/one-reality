import { useState } from 'react';
import type { TargetRecord } from '../types';
import { X, Search, CheckCircle, AlertTriangle, Loader2 } from 'lucide-react';

interface QuickCheckModalProps {
  onClose: () => void;
  onSuccess: (record: TargetRecord) => void;
}

export const QuickCheckModal = ({ onClose, onSuccess }: QuickCheckModalProps) => {
  const [domain, setDomain] = useState('');
  const [ip, setIP] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<TargetRecord | null>(null);

  const handleDetect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      // 在线检测接口同样受服务端 API Token 保护；与智能检测页共用已保存的 Token。
      const token = (localStorage.getItem('rc_api_token') || '').trim();
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      const res = await fetch('/api/targets/check', {
        method: 'POST',
        headers,
        body: JSON.stringify({ domain: domain.trim(), ip: ip.trim() }),
      });
      const data = await res.json();
      if (!res.ok || data.code !== 200) {
        throw new Error(data.error || '检测失败');
      }
      setResult(data.data);
      onSuccess(data.data);
    } catch (err: any) {
      setError(err.message || '网络请求异常');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div className="brand-icon-wrapper" style={{ width: '32px', height: '32px' }}>
              <Search size={18} />
            </div>
            <div>
              <h3 className="modal-title">在线深度指纹检测 & 资产入库</h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                对目标域名进行 TLS 1.3、X25519、H2、证书有效性及真实业务指纹审计
              </p>
            </div>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleDetect} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block' }}>
              目标域名 (Domain) *
            </label>
            <div className="input-group">
              <input
                type="text"
                placeholder="例如: gateway.icloud.com 或 www.lovelive-anime.jp"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '6px', display: 'block' }}>
              指定测试 IP (可选，留空则自动 DNS 解析)
            </label>
            <div className="input-group">
              <input
                type="text"
                placeholder="例如: 17.248.144.1"
                value={ip}
                onChange={(e) => setIP(e.target.value)}
              />
            </div>
          </div>

          <button type="submit" className="btn btn-primary" disabled={loading} style={{ marginTop: '8px' }}>
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
            {loading ? '正在执行握手与深度检测...' : '立即验证并入库'}
          </button>
        </form>

        {error && (
          <div style={{ padding: '12px', background: 'rgba(244, 63, 94, 0.12)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: 'var(--radius-md)', display: 'flex', alignItems: 'center', gap: '8px', color: '#fda4af', fontSize: '0.85rem' }}>
            <AlertTriangle size={16} />
            <span>检测未通过: {error}</span>
          </div>
        )}

        {result && (
          <div style={{ padding: '16px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 'var(--radius-md)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#6ee7b7', fontWeight: 600 }}>
              <CheckCircle size={18} />
              <span>检测成功并通过 REALITY 基线，已沉淀至本地 SQLite 资产库！</span>
            </div>
            <div className="card-specs" style={{ margin: 0 }}>
              <div className="spec-item">
                <span className="spec-label">解析 IP</span>
                <span className="spec-value" style={{ fontFamily: 'var(--font-mono)' }}>{result.ip || '未知'}</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">星级评级</span>
                <span className="spec-value" style={{ color: '#fbbf24' }}>{'★'.repeat(result.stars)} ({result.stars} 星)</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">握手延迟</span>
                <span className="spec-value">{result.handshake_ms} ms</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">ASN 归属</span>
                <span className="spec-value">{result.asn || '未知'}</span>
              </div>
              <div className="spec-item">
                <span className="spec-label">证书有效期</span>
                <span
                  className="spec-value"
                  style={{
                    color: result.cert_days <= 0 ? 'var(--accent-crimson)' : result.cert_days < 30 ? 'var(--accent-amber)' : 'inherit',
                  }}
                  title={result.cert_expire_at ? `到期时间: ${new Date(result.cert_expire_at).toLocaleString()}` : undefined}
                >
                  {result.cert_days <= 0 ? '已过期' : `${result.cert_days} 天`}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

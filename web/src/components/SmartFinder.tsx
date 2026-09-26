import { useState } from 'react';
import type { RankedTargetItem, TargetSummaryInfo, TargetItem } from '../types';
import { ConfigModal } from './ConfigModal';
import {
  Sparkles,
  Globe,
  Radio,
  Flame,
  Copy,
  Check,
  Zap,
} from 'lucide-react';

export const SmartFinder = () => {
  const [ip, setIP] = useState('');
  const [limit] = useState(12);
  const [minStars, setMinStars] = useState(3);
  const [requireNoCN, setRequireNoCN] = useState(true);
  const [useStream, setUseStream] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [summary, setSummary] = useState<TargetSummaryInfo | null>(null);
  const [targets, setTargets] = useState<RankedTargetItem[]>([]);
  const [streamProgress, setStreamProgress] = useState<string>('');

  const [selectedTarget, setSelectedTarget] = useState<TargetItem | null>(null);
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  // 快捷测试 IP
  const sampleIPs = [
    { label: '东京 Vultr (AS20473)', ip: '45.76.12.34' },
    { label: '新加坡 Linode (AS63949)', ip: '139.162.24.12' },
    { label: '美国 Oracle (AS31898)', ip: '140.238.10.55' },
    { label: '香港 GCP (AS396982)', ip: '34.92.12.80' },
  ];

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanIP = ip.trim();
    if (!cleanIP) {
      setError('请输入节点服务器 IP');
      return;
    }

    setLoading(true);
    setError('');
    setTargets([]);
    setStreamProgress('');

    if (useStream) {
      // SSE 流式响应
      const url = `/api/targets/stream?ip=${encodeURIComponent(cleanIP)}&limit=${limit}&min_stars=${minStars}&require_no_cn=${requireNoCN ? 1 : 0}`;
      const es = new EventSource(url);

      es.addEventListener('init', (evt: any) => {
        try {
          const data = JSON.parse(evt.data);
          setSummary({
            target_ip: data.ip,
            asn: data.asn,
            country: data.country,
            same_asn_hits: data.cached_hits,
            total_hits: data.need,
          });
          setStreamProgress(`已匹配到所属 ASN: ${data.asn} (${data.country})，扫描 ${data.cidr_count} 个网段...`);
        } catch (_) {}
      });

      es.addEventListener('progress', (evt: any) => {
        try {
          const data = JSON.parse(evt.data);
          setStreamProgress(`探测中: ${data.current_cidr} (已探 ${data.scanned_ips} 个 IP)`);
        } catch (_) {}
      });

      es.addEventListener('target', (evt: any) => {
        try {
          const item: TargetItem = JSON.parse(evt.data);
          setTargets((prev) => {
            const exists = prev.some((p) => p.domain === item.domain);
            if (exists) return prev;
            const isSameASN = summary?.asn && item.asn && item.asn.toUpperCase() === summary.asn.toUpperCase();
            const ranked: RankedTargetItem = {
              ...item,
              match_level: isSameASN ? 'same_asn' : 'same_country',
              score: isSameASN ? 1000 + item.stars * 30 : 250 + item.stars * 30,
            };
            return [...prev, ranked];
          });
        } catch (_) {}
      });

      es.addEventListener('done', () => {
        setLoading(false);
        setStreamProgress('');
        es.close();
      });

      es.addEventListener('error', () => {
        setLoading(false);
        setStreamProgress('');
        es.close();
        if (targets.length === 0) {
          setError('流式探测中断或无匹配目标');
        }
      });
      return;
    }

    // 默认走智能动态加权排序端点
    try {
      const url = `/api/targets/smart?ip=${encodeURIComponent(cleanIP)}&limit=${limit}&min_stars=${minStars}&require_no_cn=${requireNoCN ? 1 : 0}`;
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok || data.code !== 200) {
        throw new Error(data.error || '请求推荐目标失败');
      }
      setSummary(data.data.summary);
      setTargets(data.data.targets || []);
    } catch (err: any) {
      setError(err.message || '网络连接异常');
    } finally {
      setLoading(false);
    }
  };

  const copyDomain = (domain: string) => {
    navigator.clipboard.writeText(domain);
    setCopiedDomain(domain);
    setTimeout(() => setCopiedDomain(null), 1800);
  };

  return (
    <div>
      <section className="hero-section">
        <div className="hero-title-row">
          <div>
            <h1 className="hero-title">
              <span style={{ background: 'linear-gradient(135deg, #38bdf8, #818cf8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                同 ASN 智能权重优先
              </span>{' '}
              REALITY 伪装匹配
            </h1>
            <p className="hero-subtitle">
              输入你的落地服务器或 VPS IP，系统自动识别其所属 ASN 自治域与机房。
              <b style={{ color: '#fb923c' }}> 同 ASN 目标自动加权 1000 分置顶推荐</b>，实现拓扑同网段、毫秒级直连的天衣无缝伪装。
            </p>
          </div>
        </div>

        {/* 搜索控制区 */}
        <div className="search-box-card glass-panel">
          <form onSubmit={handleSearch} className="search-form">
            <div className="input-group">
              <Globe size={18} style={{ color: 'var(--accent-cyan)' }} />
              <input
                type="text"
                placeholder="输入服务器公网 IP，例如: 45.76.12.34"
                value={ip}
                onChange={(e) => setIP(e.target.value)}
                required
              />
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <select
                className="input-group"
                style={{ padding: '9px 12px', background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}
                value={minStars}
                onChange={(e) => setMinStars(Number(e.target.value))}
              >
                <option value={3}>⭐️ 3星及以上 (优质)</option>
                <option value={4}>⭐️ 4星及以上 (极优)</option>
                <option value={5}>⭐️ 5星极品 (顶配)</option>
                <option value={1}>全星级不限</option>
              </select>

              <button type="submit" className="btn btn-primary" disabled={loading}>
                {loading ? <Radio size={16} className="animate-spin" /> : <Sparkles size={16} />}
                {loading ? '正在计算拓扑权重...' : '智能匹配伪装'}
              </button>
            </div>
          </form>

          {/* 常用 IP 快捷填充与过滤器选项 */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-sub)' }}>快捷填入:</span>
              {sampleIPs.map((s) => (
                <button
                  key={s.ip}
                  type="button"
                  className="badge badge-global"
                  style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                  onClick={() => {
                    setIP(s.ip);
                    setTimeout(() => handleSearch(), 50);
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={requireNoCN}
                  onChange={(e) => setRequireNoCN(e.target.checked)}
                />
                排除 .cn / 境内域名
              </label>

              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', color: 'var(--text-muted)', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={useStream}
                  onChange={(e) => setUseStream(e.target.checked)}
                />
                启用实时流式探测 (SSE)
              </label>
            </div>
          </div>

          {/* 实时探测进度指示 */}
          {streamProgress && (
            <div style={{ marginTop: '14px', padding: '10px 14px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Radio size={14} className="animate-pulse" />
              <span>{streamProgress}</span>
            </div>
          )}

          {error && (
            <div style={{ marginTop: '14px', padding: '10px 14px', background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem', color: 'var(--accent-rose)' }}>
              {error}
            </div>
          )}
        </div>

        {/* 目标 IP 归属地与 ASN 拓扑元数据横幅 */}
        {summary && (
          <div className="ip-summary-banner">
            <div className="summary-meta-group">
              <div className="summary-meta-item">
                <span className="summary-meta-label">目标 IP:</span>
                <span className="summary-meta-value">{summary.target_ip}</span>
              </div>
              <div className="summary-meta-item">
                <span className="summary-meta-label">所属 ASN:</span>
                <span className="summary-meta-value" style={{ color: 'var(--accent-fire)' }}>
                  {summary.asn || '未知'}
                </span>
              </div>
              <div className="summary-meta-item">
                <span className="summary-meta-label">地区:</span>
                <span className="summary-meta-value">{summary.country || 'GLOBAL'}</span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className="badge badge-same-asn" style={{ padding: '6px 12px', fontSize: '0.82rem' }}>
                <Flame size={14} />
                同 ASN 命中: {summary.same_asn_hits} 个
              </span>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-sub)' }}>
                总计候选推荐: {targets.length} 个
              </span>
            </div>
          </div>
        )}
      </section>

      {/* 结果卡片网格 */}
      <div className="targets-grid" style={{ marginTop: '24px' }}>
        {targets.map((target) => {
          const isSameASN = target.match_level === 'same_asn';
          const isSameCountry = target.match_level === 'same_country';

          return (
            <div
              key={target.domain}
              className={`target-card glass-panel ${isSameASN ? 'highlight-asn' : ''}`}
            >
              <div>
                <div className="card-top">
                  <div className="card-title-group">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {isSameASN ? (
                        <span className="badge badge-same-asn">
                          <Flame size={12} />
                          同 ASN 极速直连
                        </span>
                      ) : isSameCountry ? (
                        <span className="badge badge-same-country">
                          <Globe size={12} />
                          同国家骨干
                        </span>
                      ) : (
                        <span className="badge badge-global">全球精选</span>
                      )}

                      <span className="star-rating">
                        {'★'.repeat(target.stars)}
                      </span>
                    </div>

                    <div className="card-domain" style={{ marginTop: '6px' }}>
                      {target.domain}
                    </div>

                    {target.page_title && (
                      <div className="card-title-text" title={target.page_title}>
                        {target.page_title}
                      </div>
                    )}
                  </div>

                  <div className="score-badge">
                    <span className="score-number">{target.score}</span>
                    <span className="score-label">匹配权重分</span>
                  </div>
                </div>

                <div className="card-specs">
                  <div className="spec-item">
                    <span className="spec-label">ASN 归属</span>
                    <span className="spec-value" style={{ color: isSameASN ? 'var(--accent-fire)' : 'var(--text-main)' }}>
                      {target.asn || '未知'} ({target.country || 'N/A'})
                    </span>
                  </div>
                  <div className="spec-item">
                    <span className="spec-label">TLS 握手延时</span>
                    <span
                      className="spec-value"
                      style={{
                        color:
                          target.handshake_ms < 50
                            ? 'var(--accent-emerald)'
                            : target.handshake_ms < 150
                            ? 'var(--accent-amber)'
                            : 'var(--text-main)',
                      }}
                    >
                      {target.handshake_ms} ms
                    </span>
                  </div>
                  <div className="spec-item">
                    <span className="spec-label">证书有效期</span>
                    <span className="spec-value">{target.cert_days} 天</span>
                  </div>
                  <div className="spec-item">
                    <span className="spec-label">HTTP 状态</span>
                    <span className="spec-value">
                      {target.status_code > 0 ? (
                        <span style={{ color: 'var(--accent-emerald)' }}>{target.status_code} OK</span>
                      ) : (
                        '443 直出'
                      )}
                    </span>
                  </div>
                </div>

                {/* 伪装特性标签 */}
                <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '14px' }}>
                  <span className="badge badge-success">TLS 1.3</span>
                  <span className="badge badge-success">X25519</span>
                  <span className="badge badge-success">H2</span>
                  {!target.is_cdn && <span className="badge badge-global">无 CDN (源站直连)</span>}
                  {target.is_default_page && (
                    <span className="badge badge-warning">{target.default_page_type || 'Nginx'} 默认页</span>
                  )}
                </div>
              </div>

              <div className="card-footer">
                <button
                  className="btn btn-secondary"
                  style={{ padding: '6px 12px', fontSize: '0.8rem' }}
                  onClick={() => copyDomain(target.domain)}
                >
                  {copiedDomain === target.domain ? <Check size={14} /> : <Copy size={14} />}
                  {copiedDomain === target.domain ? '已复制' : '复制域名'}
                </button>

                <button
                  className="btn btn-primary"
                  style={{ padding: '6px 14px', fontSize: '0.8rem' }}
                  onClick={() => setSelectedTarget(target)}
                >
                  <Zap size={14} />
                  一键生成配置
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {targets.length === 0 && !loading && (
        <div
          className="glass-panel"
          style={{
            padding: '60px 20px',
            textAlign: 'center',
            marginTop: '20px',
            color: 'var(--text-muted)',
          }}
        >
          <Sparkles size={40} style={{ color: 'var(--accent-cyan)', margin: '0 auto 16px auto', opacity: 0.6 }} />
          <h3>暂无推荐资产</h3>
          <p style={{ fontSize: '0.88rem', marginTop: '6px' }}>
            请输入你的服务器 IP，或在上方切换更宽松的星级过滤条件重新匹配。
          </p>
        </div>
      )}

      {/* 导出配置弹窗 */}
      <ConfigModal
        target={selectedTarget}
        serverIP={ip.trim()}
        onClose={() => setSelectedTarget(null)}
      />
    </div>
  );
};

import { useState, useRef, useEffect } from 'react';
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
  ShieldCheck,
  Key,
  Square,
  Play,
  Home,
  Server,
  AlertTriangle,
} from 'lucide-react';

export const SmartFinder = () => {
  const [ip, setIP] = useState('');
  const [limit] = useState(12);
  const [minStars, setMinStars] = useState(3);
  const [requireNoCN, setRequireNoCN] = useState(true);

  // 鉴权 Token
  const [apiToken, setApiToken] = useState(() => localStorage.getItem('rc_api_token') || '');
  const [showTokenSettings, setShowTokenSettings] = useState(false);

  const [loading, setLoading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');
  const [summary, setSummary] = useState<TargetSummaryInfo | null>(null);
  const [targets, setTargets] = useState<RankedTargetItem[]>([]);
  const [streamProgress, setStreamProgress] = useState<string>('');

  const [selectedTarget, setSelectedTarget] = useState<TargetItem | null>(null);
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  // 维护活动的 EventSource 实例便于主动取消
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    return () => {
      if (esRef.current) {
        esRef.current.close();
      }
    };
  }, []);

  const handleTokenChange = (val: string) => {
    setApiToken(val);
    if (val.trim()) {
      localStorage.setItem('rc_api_token', val.trim());
    } else {
      localStorage.removeItem('rc_api_token');
    }
  };

  // 快捷测试 IP
  const sampleIPs = [
    { label: '东京 Vultr (AS20473)', ip: '45.76.12.34' },
    { label: '新加坡 Linode (AS63949)', ip: '139.162.24.12' },
    { label: '美国 Oracle (AS31898)', ip: '140.238.10.55' },
    { label: '香港 GCP (AS396982)', ip: '34.92.12.80' },
  ];

  // 终止流式扫描
  const stopScan = () => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setIsScanning(false);
    setLoading(false);
    setStreamProgress('扫描已由用户手动停止，断点进度已安全保存。');
  };

  // 核心查询逻辑：优先查库返回；提前获得 ASN、国家与断点信息
  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanIP = ip.trim();
    if (!cleanIP) {
      setError('请输入节点服务器 IP');
      return;
    }

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setIsScanning(false);
    setLoading(true);
    setError('');
    setTargets([]);
    setStreamProgress('');

    try {
      const tokenParam = apiToken.trim() ? `&token=${encodeURIComponent(apiToken.trim())}` : '';
      const url = `/api/targets/smart?ip=${encodeURIComponent(cleanIP)}&limit=${limit}&min_stars=${minStars}&require_no_cn=${requireNoCN ? 1 : 0}${tokenParam}`;
      
      const headers: Record<string, string> = {};
      if (apiToken.trim()) {
        headers['Authorization'] = `Bearer ${apiToken.trim()}`;
      }

      const res = await fetch(url, { headers });
      const data = await res.json();
      if (!res.ok || data.code !== 200) {
        throw new Error(data.error || '请求匹配失败');
      }

      setSummary(data.data.summary);
      setTargets(data.data.targets || []);
    } catch (err: any) {
      setError(err.message || '网络连接异常');
    } finally {
      setLoading(false);
    }
  };

  // 触发流式扫描：提前把任务与元数据推到前端，并在后台以单 IP 粒度断点续传扫描
  const startScanStream = (scanAll: boolean = true) => {
    const cleanIP = ip.trim();
    if (!cleanIP) {
      setError('请输入节点服务器 IP');
      return;
    }

    if (esRef.current) {
      esRef.current.close();
    }

    setLoading(true);
    setIsScanning(true);
    setError('');
    setStreamProgress('正在连接流式扫描引擎，首帧提前同步 ASN 与拓扑信息...');

    const tokenParam = apiToken.trim() ? `&token=${encodeURIComponent(apiToken.trim())}` : '';
    const scanAllParam = scanAll ? '&scan_all=1' : '';
    const url = `/api/targets/stream?ip=${encodeURIComponent(cleanIP)}&limit=${limit}&min_stars=${minStars}&require_no_cn=${requireNoCN ? 1 : 0}${scanAllParam}${tokenParam}`;

    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener('init', (evt: any) => {
      try {
        const data = JSON.parse(evt.data);
        setSummary((prev) => ({
          target_ip: data.ip,
          asn: data.asn,
          asn_name: data.asn_name,
          country: data.country,
          ip_type: data.ip_type,
          is_residential: data.is_residential,
          suggest_scan: data.suggest_scan,
          cidr_count: data.cidr_count,
          total_ips: data.total_ips,
          has_checkpoint: data.has_checkpoint,
          last_checkpoint_ip: data.last_checkpoint_ip,
          same_asn_hits: data.cached_hits,
          total_hits: prev?.total_hits || data.cached_hits,
        }));

        let msg = `⚡ 提前就绪：${data.asn} (${data.country}) · ${data.is_residential ? '家庭宽带' : '机房数据中心'}`;
        if (data.cidr_count) {
          msg += `，涵盖 ${data.cidr_count} 个网段 (约 ${data.total_ips?.toLocaleString() || 0} 个 IP)`;
        }
        if (data.has_checkpoint && data.last_checkpoint_ip) {
          msg += `，发现断点，正从 ${data.last_checkpoint_ip} 自动精准续传...`;
        } else {
          msg += `，开始首轮并发探测...`;
        }
        setStreamProgress(msg);
      } catch (_) {}
    });

    es.addEventListener('progress', (evt: any) => {
      try {
        const data = JSON.parse(evt.data);
        setStreamProgress(`🔍 并发探测中: ${data.current_cidr} (已扫描 ${data.scanned_ips} 个 IP，当前探测 ${data.current_ip})`);
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

    es.addEventListener('done', (evt: any) => {
      setIsScanning(false);
      setLoading(false);
      try {
        const doneData = JSON.parse(evt.data);
        setStreamProgress(`✅ 扫描完成！本次共获得 ${doneData.total_found || 0} 个优质目标。`);
      } catch (_) {
        setStreamProgress('✅ 扫描完成。');
      }
      es.close();
      esRef.current = null;
    });

    es.addEventListener('error', () => {
      setIsScanning(false);
      setLoading(false);
      es.close();
      esRef.current = null;
      if (targets.length === 0) {
        setError('流式探测中断或鉴权失败，请检查 Token 与网络状态');
      }
    });
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
              输入你的落地服务器或 VPS IP，系统自动提前解析其所属 ASN 与网段。
              <b style={{ color: '#fb923c' }}> 本地库有即秒级返回；若无则支持一键马上扫描，精准 IP 级断点续传。</b>
            </p>
          </div>

          {/* 鉴权设置快速入口 */}
          <div>
            <button
              type="button"
              className={`btn ${apiToken ? 'btn-secondary' : 'btn-ghost'}`}
              style={{ padding: '8px 14px', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={() => setShowTokenSettings(!showTokenSettings)}
              title="配置 API 访问鉴权 Token"
            >
              {apiToken ? <ShieldCheck size={16} style={{ color: 'var(--accent-emerald)' }} /> : <Key size={16} />}
              <span>{apiToken ? 'Token 已配置' : '设置 Token'}</span>
            </button>
          </div>
        </div>

        {/* Token 设置可折叠面板 */}
        {showTokenSettings && (
          <div className="glass-panel" style={{ padding: '16px 20px', marginTop: '14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', background: 'rgba(15, 23, 42, 0.65)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.88rem', fontWeight: 600 }}>
                <Key size={15} style={{ color: 'var(--accent-cyan)' }} />
                <span>API 鉴权密钥 (Authorization Token)</span>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-sub)' }}>若后端开启了鉴权，查询与流式探测需携带此 Token</span>
            </div>
            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="password"
                placeholder="输入服务端的 API Token (如未开启则可留空)"
                value={apiToken}
                onChange={(e) => handleTokenChange(e.target.value)}
                style={{ flex: 1, padding: '8px 12px', background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', color: 'var(--text-main)', fontSize: '0.85rem' }}
              />
              {apiToken && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: '8px 14px', fontSize: '0.82rem' }}
                  onClick={() => handleTokenChange('')}
                >
                  清除
                </button>
              )}
            </div>
          </div>
        )}

        {/* 搜索控制区 */}
        <div className="search-box-card glass-panel" style={{ marginTop: '18px' }}>
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

              <button type="submit" className="btn btn-primary" disabled={loading || isScanning}>
                {loading ? <Radio size={16} className="animate-spin" /> : <Sparkles size={16} />}
                {loading ? '正在查询...' : '查询资产库'}
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
            </div>
          </div>

          {/* 实时探测进度指示 */}
          {streamProgress && (
            <div style={{ marginTop: '14px', padding: '10px 14px', background: isScanning ? 'rgba(56, 189, 248, 0.12)' : 'rgba(16, 185, 129, 0.12)', border: isScanning ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem', color: isScanning ? 'var(--accent-cyan)' : 'var(--accent-emerald)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Radio size={14} className={isScanning ? 'animate-pulse' : ''} />
                <span>{streamProgress}</span>
              </div>
              {isScanning && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: '4px 10px', fontSize: '0.76rem', display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--accent-rose)', borderColor: 'rgba(244,63,94,0.4)' }}
                  onClick={stopScan}
                >
                  <Square size={12} />
                  停止扫描
                </button>
              )}
            </div>
          )}

          {error && (
            <div style={{ marginTop: '14px', padding: '10px 14px', background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem', color: 'var(--accent-rose)' }}>
              {error}
            </div>
          )}
        </div>

        {/* 提前呈现的 IP 归属地与 ASN 拓扑元数据横幅 */}
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
                  {summary.asn || '未知'} {summary.asn_name ? `(${summary.asn_name})` : ''}
                </span>
              </div>
              <div className="summary-meta-item">
                <span className="summary-meta-label">国家/地区:</span>
                <span className="summary-meta-value">{summary.country || 'GLOBAL'}</span>
              </div>
              <div className="summary-meta-item">
                <span className="summary-meta-label">网络属性:</span>
                {summary.is_residential ? (
                  <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.78rem' }} title="家庭宽带/住宅 ISP (通常无对外公网网站与443端口，不建议扫描)">
                    <Home size={12} />
                    住宅家宽 / ISP
                  </span>
                ) : (
                  <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.78rem' }} title="数据中心机房/云服务商 (适合托管真实业务与伪装选型)">
                    <Server size={12} />
                    机房 / 数据中心
                  </span>
                )}
              </div>
              {summary.cidr_count !== undefined && summary.cidr_count > 0 && (
                <div className="summary-meta-item">
                  <span className="summary-meta-label">网段规模:</span>
                  <span className="summary-meta-value" style={{ color: 'var(--accent-cyan)' }}>
                    {summary.cidr_count} 段 ({summary.total_ips?.toLocaleString() || 0} IPs)
                  </span>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className="badge badge-same-asn" style={{ padding: '6px 12px', fontSize: '0.82rem' }}>
                <Flame size={14} />
                同 ASN 库内命中: {summary.same_asn_hits} 个
              </span>

              {/* 若已有结果，亦可在此快速触发增量流式扫描 */}
              {!isScanning ? (
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: '6px 12px', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '6px' }}
                  onClick={() => startScanStream(true)}
                  disabled={loading}
                >
                  <Play size={13} style={{ color: 'var(--accent-cyan)' }} />
                  {summary.has_checkpoint ? '继续断点扫描' : '启动 ASN 扫描'}
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: '6px 12px', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-rose)', borderColor: 'rgba(244,63,94,0.4)' }}
                  onClick={stopScan}
                >
                  <Square size={13} />
                  停止扫描
                </button>
              )}
            </div>
          </div>
        )}
      </section>

      {/* 核心业务：当数据库无资产时，展示醒目的【马上扫描】开关面板 */}
      {summary && targets.length === 0 && !loading && !isScanning && (
        <div
          className="glass-panel"
          style={{
            marginTop: '24px',
            padding: '36px 28px',
            borderRadius: 'var(--radius-lg)',
            border: summary.is_residential ? '1px solid rgba(245, 158, 11, 0.4)' : '1px solid rgba(56, 189, 248, 0.35)',
            background: summary.is_residential
              ? 'linear-gradient(180deg, rgba(30, 27, 24, 0.85) 0%, rgba(20, 20, 25, 0.7) 100%)'
              : 'linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.6) 100%)',
            textAlign: 'center',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: summary.is_residential ? 'rgba(245, 158, 11, 0.15)' : 'rgba(249, 115, 22, 0.15)',
              border: summary.is_residential ? '1px solid rgba(245, 158, 11, 0.4)' : '1px solid rgba(249, 115, 22, 0.4)',
              marginBottom: '16px',
            }}
          >
            {summary.is_residential ? (
              <AlertTriangle size={28} style={{ color: 'var(--accent-amber)' }} />
            ) : (
              <Zap size={28} style={{ color: '#fb923c' }} />
            )}
          </div>

          <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '8px' }}>
            {summary.is_residential
              ? `⚠️ 检测到该 IP 为家庭宽带网络 (${summary.asn} · ${summary.asn_name || summary.country})`
              : `该机房 ASN (${summary.asn} · ${summary.asn_name || summary.country}) 本地库暂无收录资产`}
          </h3>

          <p style={{ color: 'var(--text-sub)', fontSize: '0.9rem', maxWidth: '680px', margin: '0 auto 20px auto', lineHeight: 1.6 }}>
            {summary.is_residential ? (
              <span>
                <strong style={{ color: 'var(--accent-amber)' }}>不建议扫描：</strong>
                家庭宽带几乎不存在对外开放 443 端口的真实公网网站与合法证书，全网探测绝大部分为握手超时，难以获得可用 REALITY 伪装目标。
                建议优先更换为云厂商或 IDC 机房 IP。若确需探索该网段，仍可尝试强制扫描。
              </span>
            ) : (
              <span>
                已为您提前锁定该机房归属网络，共计识别出{' '}
                <strong style={{ color: 'var(--accent-cyan)' }}>{summary.cidr_count || 0} 个网段</strong>，
                涵盖约 <strong style={{ color: 'var(--accent-cyan)' }}>{summary.total_ips?.toLocaleString() || 0} 个 IP 地址</strong>。
                {summary.has_checkpoint ? (
                  <span style={{ display: 'block', color: 'var(--accent-emerald)', marginTop: '6px' }}>
                    🔄 发现历史断点记录，上次已扫描至 <b>{summary.last_checkpoint_ip}</b>，开启后将从该 IP 精确续传！
                  </span>
                ) : (
                  <span style={{ display: 'block', marginTop: '6px' }}>
                    打开下方开关即刻启动并发流水线，边扫边流式返回入库。
                  </span>
                )}
              </span>
            )}
          </p>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px' }}>
            <button
              type="button"
              className="btn"
              style={{
                padding: '12px 28px',
                fontSize: '1rem',
                fontWeight: 600,
                color: '#fff',
                background: summary.is_residential
                  ? 'linear-gradient(135deg, #d97706, #b45309)'
                  : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                boxShadow: summary.is_residential
                  ? '0 0 20px rgba(217, 119, 6, 0.35)'
                  : '0 0 25px rgba(99, 102, 241, 0.4)',
                border: 'none',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '10px',
                cursor: 'pointer',
              }}
              onClick={() => startScanStream(true)}
            >
              {summary.is_residential ? <AlertTriangle size={18} /> : <Zap size={18} />}
              {summary.is_residential ? '强制尝试扫描该家宽 ASN' : '马上扫描该 ASN (流式探测)'}
            </button>
          </div>
        </div>
      )}

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
                    <span
                      className="spec-value"
                      style={{
                        color: target.cert_days <= 0 ? 'var(--accent-crimson)' : target.cert_days < 30 ? 'var(--accent-amber)' : 'inherit',
                      }}
                      title={target.cert_expire_at ? `到期时间: ${new Date(target.cert_expire_at).toLocaleString()}` : undefined}
                    >
                      {target.cert_days <= 0 ? '已过期' : `${target.cert_days} 天`}
                    </span>
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
                  {target.tags?.includes('cert_renew_delayed') && (
                    <span className="badge badge-warning" title="证书剩余不足30天且尚未自动续期">
                      疑似未自动续期
                    </span>
                  )}
                  {target.is_default_page && (
                    <span className="badge badge-warning">{target.default_page_type || 'Nginx'} 默认页</span>
                  )}
                  {target.source === 'scan' && (
                    <span className="badge" style={{ background: 'rgba(56, 189, 248, 0.2)', color: 'var(--accent-cyan)' }}>现场即时新扫</span>
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

      {!summary && targets.length === 0 && !loading && (
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
          <h3>输入落地服务器 IP 开始匹配</h3>
          <p style={{ fontSize: '0.88rem', marginTop: '6px' }}>
            系统将提前识别其所属 ASN 自治域与拓扑规模，精准查找同 ASN 优质 REALITY 伪装目标。
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

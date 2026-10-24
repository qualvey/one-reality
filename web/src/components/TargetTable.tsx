import { useState, useEffect } from 'react';
import type { TargetRecord, TargetItem } from '../types';
import { ConfigModal } from './ConfigModal';
import { QuickCheckModal } from './QuickCheckModal';
import {
  Search,
  Plus,
  RefreshCw,
  Trash2,
  Power,
  Zap,
  Copy,
  Check,
  Filter,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

export const TargetTable = () => {
  const [items, setItems] = useState<TargetRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [loading, setLoading] = useState(false);

  // 筛选条件
  const [keyword, setKeyword] = useState('');
  const [asn, setASN] = useState('');
  const [country, setCountry] = useState('');
  const [minStars, setMinStars] = useState(0);
  const [isActive, setIsActive] = useState<string>('all');
  const [sortBy, setSortBy] = useState('stars_desc');

  // 进阶选型偏好过滤 (Filter 策略)
  const [requireNoCDN, setRequireNoCDN] = useState(false);
  const [requireNoDefaultPage, setRequireNoDefaultPage] = useState(false);
  const [requireNoHot, setRequireNoHot] = useState(false);
  const [maxHandshakeMS, setMaxHandshakeMS] = useState(0);
  const [minCertDays, setMinCertDays] = useState(0);
  const [excludeStatus403, setExcludeStatus403] = useState(false);

  const [selectedTarget, setSelectedTarget] = useState<TargetItem | null>(null);
  const [showCheckModal, setShowCheckModal] = useState(false);
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  const fetchTargets = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
        sort_by: sortBy,
      });

      if (keyword.trim()) params.append('keyword', keyword.trim());
      if (asn.trim()) params.append('asn', asn.trim());
      if (country.trim()) params.append('country', country.trim());
      if (minStars > 0) params.append('min_stars', minStars.toString());
      if (isActive === 'active') params.append('is_active', '1');
      if (isActive === 'inactive') params.append('is_active', '0');

      // 选型偏好过滤参数下推
      if (requireNoCDN) params.append('require_no_cdn', '1');
      if (requireNoDefaultPage) params.append('require_no_default_page', '1');
      if (requireNoHot) params.append('require_no_hot', '1');
      if (maxHandshakeMS > 0) params.append('max_handshake_ms', maxHandshakeMS.toString());
      if (minCertDays > 0) params.append('min_cert_days', minCertDays.toString());
      if (excludeStatus403) params.append('exclude_status', '400,401,403,404,429,500,502,503');

      const res = await fetch(`/api/targets?${params.toString()}`);
      const data = await res.json();
      if (res.ok && data.code === 200) {
        setItems(data.data.items || []);
        setTotal(data.data.total || 0);
      }
    } catch (err) {
      console.error('Failed to load targets:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTargets();
  }, [page, sortBy, minStars, isActive, requireNoCDN, requireNoDefaultPage, requireNoHot, maxHandshakeMS, minCertDays, excludeStatus403]);

  const applyDefaultFilter = async () => {
    try {
      const res = await fetch('/api/filter/default');
      const data = await res.json();
      if (res.ok && data.code === 200 && data.data) {
        const def = data.data;
        setRequireNoCDN(!!def.require_no_cdn);
        setRequireNoDefaultPage(!!def.require_no_default_page);
        setRequireNoHot(!!def.require_no_hot);
        setMaxHandshakeMS(def.max_handshake_ms || 0);
        setMinCertDays(def.min_cert_days || 0);
        setMinStars(def.min_stars || 0);
        setExcludeStatus403(Array.isArray(def.exclude_status) && def.exclude_status.length > 0);
        setPage(1);
      }
    } catch (err) {
      console.error('Failed to load default filter:', err);
    }
  };

  const resetAllFilters = () => {
    setKeyword('');
    setASN('');
    setCountry('');
    setMinStars(0);
    setIsActive('all');
    setSortBy('stars_desc');
    setRequireNoCDN(false);
    setRequireNoDefaultPage(false);
    setRequireNoHot(false);
    setMaxHandshakeMS(0);
    setMinCertDays(0);
    setExcludeStatus403(false);
    setPage(1);
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchTargets();
  };

  const toggleActive = async (target: TargetRecord) => {
    try {
      const res = await fetch(`/api/targets/${encodeURIComponent(target.domain)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: !target.is_active }),
      });
      if (res.ok) {
        setItems((prev) =>
          prev.map((item) =>
            item.domain === target.domain ? { ...item, is_active: !target.is_active } : item
          )
        );
      }
    } catch (err) {
      console.error('Failed to toggle active state:', err);
    }
  };

  const deleteTarget = async (domain: string) => {
    if (!window.confirm(`确定要从数据库中物理删除目标 [${domain}] 吗？`)) return;

    try {
      const res = await fetch(`/api/targets/${encodeURIComponent(domain)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        setItems((prev) => prev.filter((item) => item.domain !== domain));
        setTotal((prev) => Math.max(0, prev - 1));
      }
    } catch (err) {
      console.error('Failed to delete target:', err);
    }
  };

  const copyDomain = (domain: string) => {
    navigator.clipboard.writeText(domain);
    setCopiedDomain(domain);
    setTimeout(() => setCopiedDomain(null), 1500);
  };

  const openConfigModal = (row: TargetRecord) => {
    const item: TargetItem = {
      ...row,
      created_at: row.last_checked_at,
    };
    setSelectedTarget(item);
  };

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>REALITY 资产全量库</h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            管理已收录的 TLS 1.3 / X25519 域名资产，支持状态巡检、启停切换与实时单测入库
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button className="btn btn-secondary" onClick={() => fetchTargets()}>
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            刷新
          </button>
          <button className="btn btn-primary" onClick={() => setShowCheckModal(true)}>
            <Plus size={16} />
            在线探测并入库
          </button>
        </div>
      </div>

      {/* 过滤筛选条 */}
      <div className="glass-panel" style={{ padding: '16px 20px', marginBottom: '20px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div className="input-group" style={{ flex: '1 1 240px' }}>
            <Search size={16} style={{ color: 'var(--text-sub)' }} />
            <input
              type="text"
              placeholder="搜索域名、IP 或网站标题..."
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
            />
          </div>

          <div className="input-group" style={{ width: '130px' }}>
            <input
              type="text"
              placeholder="ASN 编号"
              value={asn}
              onChange={(e) => setASN(e.target.value)}
            />
          </div>

          <div className="input-group" style={{ width: '100px' }}>
            <input
              type="text"
              placeholder="国家代码"
              value={country}
              onChange={(e) => setCountry(e.target.value)}
            />
          </div>

          <select
            className="input-group"
            style={{ width: '130px', padding: '10px', background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}
            value={minStars}
            onChange={(e) => {
              setMinStars(Number(e.target.value));
              setPage(1);
            }}
          >
            <option value={0}>星级不限</option>
            <option value={3}>3 星及以上</option>
            <option value={4}>4 星及以上</option>
            <option value={5}>5 星极品</option>
          </select>

          <select
            className="input-group"
            style={{ width: '120px', padding: '10px', background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}
            value={isActive}
            onChange={(e) => {
              setIsActive(e.target.value);
              setPage(1);
            }}
          >
            <option value="all">状态全部</option>
            <option value="active">仅活跃有效</option>
            <option value="inactive">仅已停用</option>
          </select>

          <select
            className="input-group"
            style={{ width: '130px', padding: '10px', background: 'var(--bg-input)', color: 'var(--text-main)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}
            value={sortBy}
            onChange={(e) => {
              setSortBy(e.target.value);
              setPage(1);
            }}
          >
            <option value="stars_desc">星级从高到低</option>
            <option value="handshake_asc">延迟从低到高</option>
            <option value="recent_desc">最近巡检时间</option>
          </select>

          <button type="submit" className="btn btn-secondary">
            <Filter size={14} />
            筛选
          </button>

          {/* 选型偏好过滤快捷开关栏 (Filter Strategies) */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', width: '100%', marginTop: '10px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px', marginRight: '4px' }}>
              <Filter size={13} /> 选型偏好:
            </span>

            <button
              type="button"
              style={{
                fontSize: '0.75rem',
                padding: '4px 10px',
                borderRadius: '12px',
                cursor: 'pointer',
                border: '1px solid',
                borderColor: requireNoCDN ? 'var(--primary)' : 'var(--border-subtle)',
                background: requireNoCDN ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: requireNoCDN ? 'var(--primary)' : 'var(--text-sub)',
                fontWeight: requireNoCDN ? 600 : 400,
                transition: 'all 0.15s ease',
              }}
              onClick={() => { setRequireNoCDN(!requireNoCDN); setPage(1); }}
            >
              {requireNoCDN ? '✓ 排除 CDN' : '+ 排除 CDN'}
            </button>

            <button
              type="button"
              style={{
                fontSize: '0.75rem',
                padding: '4px 10px',
                borderRadius: '12px',
                cursor: 'pointer',
                border: '1px solid',
                borderColor: requireNoDefaultPage ? 'var(--primary)' : 'var(--border-subtle)',
                background: requireNoDefaultPage ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: requireNoDefaultPage ? 'var(--primary)' : 'var(--text-sub)',
                fontWeight: requireNoDefaultPage ? 600 : 400,
                transition: 'all 0.15s ease',
              }}
              onClick={() => { setRequireNoDefaultPage(!requireNoDefaultPage); setPage(1); }}
            >
              {requireNoDefaultPage ? '✓ 排除默认页' : '+ 排除默认页'}
            </button>

            <button
              type="button"
              style={{
                fontSize: '0.75rem',
                padding: '4px 10px',
                borderRadius: '12px',
                cursor: 'pointer',
                border: '1px solid',
                borderColor: requireNoHot ? 'var(--primary)' : 'var(--border-subtle)',
                background: requireNoHot ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: requireNoHot ? 'var(--primary)' : 'var(--text-sub)',
                fontWeight: requireNoHot ? 600 : 400,
                transition: 'all 0.15s ease',
              }}
              onClick={() => { setRequireNoHot(!requireNoHot); setPage(1); }}
            >
              {requireNoHot ? '✓ 排除热门大站' : '+ 排除热门大站'}
            </button>

            <button
              type="button"
              style={{
                fontSize: '0.75rem',
                padding: '4px 10px',
                borderRadius: '12px',
                cursor: 'pointer',
                border: '1px solid',
                borderColor: excludeStatus403 ? 'var(--primary)' : 'var(--border-subtle)',
                background: excludeStatus403 ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: excludeStatus403 ? 'var(--primary)' : 'var(--text-sub)',
                fontWeight: excludeStatus403 ? 600 : 400,
                transition: 'all 0.15s ease',
              }}
              onClick={() => { setExcludeStatus403(!excludeStatus403); setPage(1); }}
            >
              {excludeStatus403 ? '✓ 排除异常/403状态码' : '+ 排除异常/403状态码'}
            </button>

            <select
              style={{
                fontSize: '0.75rem',
                padding: '4px 8px',
                borderRadius: '12px',
                border: '1px solid var(--border-subtle)',
                background: maxHandshakeMS > 0 ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: maxHandshakeMS > 0 ? 'var(--primary)' : 'var(--text-sub)',
              }}
              value={maxHandshakeMS}
              onChange={(e) => { setMaxHandshakeMS(Number(e.target.value)); setPage(1); }}
            >
              <option value={0}>延迟不限</option>
              <option value={150}>延迟 ≤ 150ms</option>
              <option value={300}>延迟 ≤ 300ms</option>
              <option value={500}>延迟 ≤ 500ms</option>
              <option value={800}>延迟 ≤ 800ms</option>
            </select>

            <select
              style={{
                fontSize: '0.75rem',
                padding: '4px 8px',
                borderRadius: '12px',
                border: '1px solid var(--border-subtle)',
                background: minCertDays > 0 ? 'rgba(59, 130, 246, 0.15)' : 'var(--bg-input)',
                color: minCertDays > 0 ? 'var(--primary)' : 'var(--text-sub)',
              }}
              value={minCertDays}
              onChange={(e) => { setMinCertDays(Number(e.target.value)); setPage(1); }}
            >
              <option value={0}>证书天数不限</option>
              <option value={7}>证书剩余 ≥ 7天</option>
              <option value={15}>证书剩余 ≥ 15天</option>
              <option value={30}>证书剩余 ≥ 30天</option>
              <option value={60}>证书剩余 ≥ 60天</option>
            </select>

            <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', padding: '3px 8px', height: '26px' }}
                onClick={applyDefaultFilter}
                title="载入 config.yaml 中的默认选型策略"
              >
                载入配置偏好
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ fontSize: '0.75rem', padding: '3px 8px', height: '26px' }}
                onClick={resetAllFilters}
                title="清空所有过滤条件"
              >
                重置
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* 数据表格 */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>域名 (Domain)</th>
              <th>ASN / 国家</th>
              <th>解析 IP</th>
              <th>星级评级</th>
              <th>握手延迟</th>
              <th>证书天数</th>
              <th>状态</th>
              <th>最后巡检</th>
              <th style={{ textAlign: 'right' }}>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.domain}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{row.domain}</span>
                    <button
                      className="btn-icon"
                      style={{ padding: '2px 5px', fontSize: '0.7rem' }}
                      title="复制域名"
                      onClick={() => copyDomain(row.domain)}
                    >
                      {copiedDomain === row.domain ? <Check size={12} color="var(--accent-emerald)" /> : <Copy size={12} />}
                    </button>
                  </div>
                  {row.page_title && (
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-sub)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {row.page_title}
                    </div>
                  )}
                </td>
                <td>
                  <span className="badge badge-global">{row.asn || 'AS-'}</span>
                  {row.country && (
                    <span className="badge" style={{ marginLeft: '4px', background: 'rgba(255,255,255,0.05)' }}>
                      {row.country}
                    </span>
                  )}
                </td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>{row.ip}:{row.port || 443}</span>
                </td>
                <td>
                  <span className="star-rating">{'★'.repeat(row.stars)}</span>
                </td>
                <td>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      color: row.handshake_ms < 60 ? 'var(--accent-emerald)' : row.handshake_ms < 150 ? 'var(--accent-amber)' : 'var(--text-muted)',
                    }}
                  >
                    {row.handshake_ms} ms
                  </span>
                </td>
                <td>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.82rem',
                        fontWeight: 600,
                        color: row.cert_days <= 0 ? 'var(--accent-crimson)' : row.cert_days < 30 ? 'var(--accent-amber)' : 'inherit',
                      }}
                      title={row.cert_expire_at ? `证书到期时间: ${new Date(row.cert_expire_at).toLocaleString()}` : undefined}
                    >
                      {row.cert_days <= 0 ? '已过期' : `${row.cert_days} 天`}
                    </span>
                    {row.tags?.includes('cert_renew_delayed') && (
                      <span
                        className="badge badge-warning"
                        style={{ fontSize: '0.65rem', padding: '1px 5px', width: 'fit-content', whiteSpace: 'nowrap' }}
                        title="证书剩余不足30天且尚未见自动续期，存在失效风险"
                      >
                        疑似未自动续期
                      </span>
                    )}
                  </div>
                </td>
                <td>
                  <span className={`badge ${row.is_active ? 'badge-success' : 'badge-danger'}`}>
                    {row.is_active ? '活跃' : '已停用'}
                  </span>
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-sub)' }}>
                  {new Date(row.last_checked_at).toLocaleDateString()}
                </td>
                <td style={{ textAlign: 'right' }}>
                  <div style={{ display: 'inline-flex', gap: '6px' }}>
                    <button
                      className="btn-icon"
                      title={row.is_active ? '停用此资产' : '重新激活'}
                      style={{ color: row.is_active ? 'var(--accent-emerald)' : 'var(--text-sub)' }}
                      onClick={() => toggleActive(row)}
                    >
                      <Power size={14} />
                    </button>
                    <button
                      className="btn-icon"
                      title="生成配置"
                      onClick={() => openConfigModal(row)}
                    >
                      <Zap size={14} style={{ color: 'var(--accent-cyan)' }} />
                    </button>
                    <button
                      className="btn-icon"
                      title="删除此目标"
                      onClick={() => deleteTarget(row.domain)}
                    >
                      <Trash2 size={14} style={{ color: 'var(--accent-rose)' }} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}

            {items.length === 0 && !loading && (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-sub)' }}>
                  暂未找到匹配的资产记录
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* 分页控制栏 */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '18px', padding: '0 4px' }}>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          共 <b style={{ color: 'var(--text-main)' }}>{total}</b> 条资产记录 · 当前第 {page} / {totalPages} 页
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn btn-secondary"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            <ChevronLeft size={16} /> 上一页
          </button>
          <button
            className="btn btn-secondary"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页 <ChevronRight size={16} />
          </button>
        </div>
      </div>

      {/* 弹窗支持 */}
      <ConfigModal
        target={selectedTarget}
        serverIP={selectedTarget?.ip || ''}
        onClose={() => setSelectedTarget(null)}
      />

      {showCheckModal && (
        <QuickCheckModal
          onClose={() => setShowCheckModal(false)}
          onSuccess={() => {
            fetchTargets();
          }}
        />
      )}
    </div>
  );
};

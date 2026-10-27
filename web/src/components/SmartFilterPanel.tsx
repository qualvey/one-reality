import { useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { SmartFilterOptions } from '../types';
import { Globe, RotateCcw, Search, Server, ShieldCheck, SlidersHorizontal, Sparkles, X, Clock, Filter } from 'lucide-react';

interface SmartFilterPanelProps {
  filter: SmartFilterOptions;
  setFilter: Dispatch<SetStateAction<SmartFilterOptions>>;
  resultCount?: number;
  totalCount?: number;
  onReset?: () => void;
  onLoadDefault?: () => void;
  requireNoHot?: boolean;
  onRequireNoHotChange?: (value: boolean) => void;
  showKeyword?: boolean;
  showMatchScope?: boolean;
}

const EMPTY_FILTER: SmartFilterOptions = {
  minStars: 0,
  maxHandshakeMS: 0,
  requireNoCDN: false,
  requireNoDefaultPage: false,
  requireNoCN: false,
  minCertDays: 0,
  matchScope: 'all',
  statusFilter: 'all',
  keyword: '',
  domainSuffixes: '',
};

export const SmartFilterPanel = ({
  filter,
  setFilter,
  resultCount,
  totalCount,
  onReset,
  onLoadDefault,
  requireNoHot,
  onRequireNoHotChange,
  showKeyword = true,
  showMatchScope = true,
}: SmartFilterPanelProps) => {
  const [showAdvanced, setShowAdvanced] = useState(false);

  const activeFilterCount = useMemo(() => {
    return [
      filter.minStars > 0,
      filter.maxHandshakeMS > 0,
      filter.requireNoCDN,
      filter.requireNoDefaultPage,
      filter.requireNoCN,
      filter.minCertDays > 0,
      showMatchScope && filter.matchScope !== 'all',
      filter.statusFilter !== 'all',
      filter.keyword.trim().length > 0,
      filter.domainSuffixes.trim().length > 0,
      requireNoHot === true,
    ].filter(Boolean).length;
  }, [filter, requireNoHot, showMatchScope]);

  const isSuffixSelected = (suffix: string) => {
    const selected = filter.domainSuffixes
      .split(',')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean)
      .map((item) => (item.startsWith('.') ? item : `.${item}`));
    return selected.includes(suffix.toLowerCase());
  };

  const toggleSuffix = (suffix: string) => {
    setFilter((previous) => {
      const clean = suffix.toLowerCase();
      const selected = previous.domainSuffixes
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
        .map((item) => (item.startsWith('.') ? item : `.${item}`));
      const next = selected.includes(clean)
        ? selected.filter((item) => item !== clean)
        : [...selected, clean];
      return { ...previous, domainSuffixes: next.join(', ') };
    });
  };

  const reset = () => {
    if (onReset) {
      onReset();
      return;
    }
    setFilter(EMPTY_FILTER);
    onRequireNoHotChange?.(false);
  };

  const applyRecommended = () => {
    setFilter((previous) => ({
      ...previous,
      minStars: 3,
      maxHandshakeMS: 150,
      requireNoCDN: true,
      requireNoDefaultPage: true,
      requireNoCN: true,
      minCertDays: 15,
      statusFilter: 'all',
      domainSuffixes: '.com',
    }));
    onRequireNoHotChange?.(true);
  };

  return (
    <div className="filter-panel-card">
      <div className="filter-primary-row">
        <div className="filter-chips-group">
          <span className="filter-field-label"><Filter size={13} /> 星级偏好:</span>
          {[0, 3, 4, 5].map((stars) => (
            <button
              key={stars}
              type="button"
              className={`filter-chip ${filter.minStars === stars ? 'active' : ''}`}
              onClick={() => setFilter((previous) => ({ ...previous, minStars: stars }))}
            >
              {stars === 0 ? '全部' : `⭐️ ${stars}星${stars === 5 ? '极品' : '+'}`}
            </button>
          ))}
        </div>

        <div className="filter-chips-group">
          <button
            type="button"
            className={`filter-chip ${filter.requireNoCDN ? 'active' : ''}`}
            onClick={() => setFilter((previous) => ({ ...previous, requireNoCDN: !previous.requireNoCDN }))}
            title="仅保留源站直连目标，排除 CDN 域名"
          >
            ⚡ 源站直连 (排除 CDN)
          </button>
          <button
            type="button"
            className={`filter-chip ${filter.requireNoCN ? 'active' : ''}`}
            onClick={() => setFilter((previous) => ({ ...previous, requireNoCN: !previous.requireNoCN }))}
          >
            🛡️ 排除 .cn 境内域名
          </button>
          <button
            type="button"
            className={`filter-chip ${filter.requireNoDefaultPage ? 'active-warning' : ''}`}
            onClick={() => setFilter((previous) => ({ ...previous, requireNoDefaultPage: !previous.requireNoDefaultPage }))}
          >
            📄 排除默认欢迎页
          </button>
          {onRequireNoHotChange && (
            <button
              type="button"
              className={`filter-chip ${requireNoHot ? 'active-warning' : ''}`}
              onClick={() => onRequireNoHotChange(!requireNoHot)}
            >
              🔥 排除热门大站
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '10px', paddingTop: '10px', borderTop: '1px solid rgba(255, 255, 255, 0.05)', flexWrap: 'wrap', gap: '8px' }}>
        <div className="filter-chips-group">
          <span className="filter-field-label"><Globe size={13} style={{ color: 'var(--accent-cyan)' }} /> 域名后缀:</span>
          <button type="button" className={`filter-chip ${!filter.domainSuffixes ? 'active' : ''}`} onClick={() => setFilter((previous) => ({ ...previous, domainSuffixes: '' }))}>
            全部后缀
          </button>
          {['.com', '.net', '.org', '.io', '.xyz'].map((suffix) => (
            <button key={suffix} type="button" className={`filter-chip ${isSuffixSelected(suffix) ? 'active' : ''}`} onClick={() => toggleSuffix(suffix)}>
              {suffix === '.com' ? '⭐️ .com' : suffix}
            </button>
          ))}
        </div>
        <button type="button" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={() => setShowAdvanced((value) => !value)}>
          <SlidersHorizontal size={13} /> {showAdvanced ? '收起高级筛选' : `高级筛选${activeFilterCount > 0 ? ` (${activeFilterCount})` : ''}`}
        </button>
      </div>

      {showAdvanced && (
        <div className="filter-drawer">
          <div className="filter-field">
            <label className="filter-field-label"><Clock size={13} style={{ color: 'var(--accent-cyan)' }} /> 握手延迟上限</label>
            <select value={filter.maxHandshakeMS} onChange={(event) => setFilter((previous) => ({ ...previous, maxHandshakeMS: Number(event.target.value) }))}>
              <option value={0}>不限延迟</option>
              <option value={60}>≤ 60 ms (极致)</option>
              <option value={100}>≤ 100 ms (极速)</option>
              <option value={150}>≤ 150 ms (优良)</option>
              <option value={220}>≤ 220 ms (标准)</option>
              <option value={350}>≤ 350 ms (宽松)</option>
            </select>
          </div>
          <div className="filter-field">
            <label className="filter-field-label"><ShieldCheck size={13} style={{ color: 'var(--accent-emerald)' }} /> 证书剩余有效天数</label>
            <select value={filter.minCertDays} onChange={(event) => setFilter((previous) => ({ ...previous, minCertDays: Number(event.target.value) }))}>
              <option value={0}>不限天数</option>
              <option value={15}>≥ 15 天</option>
              <option value={30}>≥ 30 天</option>
              <option value={60}>≥ 60 天</option>
            </select>
          </div>
          <div className="filter-field">
            <label className="filter-field-label"><Server size={13} /> HTTP 响应状态</label>
            <select value={filter.statusFilter} onChange={(event) => setFilter((previous) => ({ ...previous, statusFilter: event.target.value as SmartFilterOptions['statusFilter'] }))}>
              <option value="all">全部 (包含 443 协议直通)</option>
              <option value="success_only">2xx/3xx / 443 直通 (排除 4xx/5xx)</option>
            </select>
          </div>
          {showMatchScope && (
            <div className="filter-field">
              <label className="filter-field-label"><Globe size={13} style={{ color: 'var(--accent-fire)' }} /> 匹配范畴</label>
              <select value={filter.matchScope} onChange={(event) => setFilter((previous) => ({ ...previous, matchScope: event.target.value as SmartFilterOptions['matchScope'] }))}>
                <option value="all">全量资产</option>
                <option value="same_asn">仅同 ASN</option>
                <option value="same_country">同 ASN / 同国家</option>
              </select>
            </div>
          )}
          <div className="filter-field" style={{ gridColumn: 'span 2' }}>
            <label className="filter-field-label"><Globe size={13} style={{ color: 'var(--accent-cyan)' }} /> 指定域名后缀 (逗号分隔)</label>
            <div style={{ position: 'relative' }}>
              <input type="text" placeholder="例如: .com, .net, .org" value={filter.domainSuffixes} onChange={(event) => setFilter((previous) => ({ ...previous, domainSuffixes: event.target.value }))} style={{ width: '100%', paddingRight: '28px' }} />
              {filter.domainSuffixes && <button type="button" onClick={() => setFilter((previous) => ({ ...previous, domainSuffixes: '' }))} style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-sub)', cursor: 'pointer' }} title="清空后缀"><X size={13} /></button>}
            </div>
          </div>
          {showKeyword && (
            <div className="filter-field" style={{ gridColumn: 'span 2' }}>
              <label className="filter-field-label"><Search size={13} style={{ color: 'var(--accent-cyan)' }} /> 域名或标题实时过滤</label>
              <div style={{ position: 'relative' }}>
                <input type="text" placeholder="输入关键字即时过滤 (如 cloud, debian, microsoft)..." value={filter.keyword} onChange={(event) => setFilter((previous) => ({ ...previous, keyword: event.target.value }))} style={{ width: '100%', paddingRight: '28px' }} />
                {filter.keyword && <button type="button" onClick={() => setFilter((previous) => ({ ...previous, keyword: '' }))} style={{ position: 'absolute', right: '8px', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-sub)', cursor: 'pointer' }} title="清空关键词"><X size={13} /></button>}
              </div>
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', paddingBottom: '2px' }}>
            <button type="button" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={applyRecommended}><Sparkles size={13} style={{ color: 'var(--accent-cyan)' }} /> 推荐配置</button>
            {onLoadDefault && <button type="button" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={onLoadDefault}>载入配置偏好</button>}
            <button type="button" className="btn btn-ghost" style={{ padding: '6px 12px', fontSize: '0.8rem' }} onClick={reset}><RotateCcw size={13} /> 清空条件</button>
          </div>
        </div>
      )}

      {(resultCount !== undefined || totalCount !== undefined || activeFilterCount > 0) && (
        <div className="filter-summary-bar">
          <span>
            当前展示 <strong style={{ color: 'var(--accent-cyan)' }}>{resultCount ?? totalCount ?? 0}</strong> 个目标
            {totalCount !== undefined && resultCount !== undefined && totalCount !== resultCount && <span>（筛选前 {totalCount} 个）</span>}
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
            {filter.minStars > 0 && <span className="badge badge-warning" style={{ fontSize: '0.72rem' }}>≥{filter.minStars}星</span>}
            {filter.maxHandshakeMS > 0 && <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>≤{filter.maxHandshakeMS}ms</span>}
            {filter.requireNoCDN && <span className="badge badge-success" style={{ fontSize: '0.72rem' }}>源站直连</span>}
            {filter.requireNoCN && <span className="badge badge-global" style={{ fontSize: '0.72rem' }}>无 .cn</span>}
            {filter.requireNoDefaultPage && <span className="badge badge-warning" style={{ fontSize: '0.72rem' }}>无默认页</span>}
            {filter.minCertDays > 0 && <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>≥{filter.minCertDays}天证书</span>}
            {filter.domainSuffixes.trim() && <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>后缀: {filter.domainSuffixes}</span>}
            {filter.keyword.trim() && <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>词: {filter.keyword}</span>}
            {activeFilterCount > 0 && <button type="button" onClick={reset} style={{ background: 'none', border: 'none', color: 'var(--text-sub)', fontSize: '0.72rem', cursor: 'pointer', textDecoration: 'underline' }}>重置</button>}
          </div>
        </div>
      )}
    </div>
  );
};

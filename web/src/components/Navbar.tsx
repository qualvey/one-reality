import { Shield, Sparkles, Database, Globe2, BarChart3, RefreshCw } from 'lucide-react';

interface NavbarProps {
  currentTab: 'smart' | 'assets' | 'asns' | 'stats';
  onTabChange: (tab: 'smart' | 'assets' | 'asns' | 'stats') => void;
  serviceOnline: boolean;
  onRefreshStats: () => void;
}

export const Navbar = ({
  currentTab,
  onTabChange,
  serviceOnline,
  onRefreshStats,
}: NavbarProps) => {
  return (
    <header className="navbar">
      <div className="nav-brand" onClick={() => onTabChange('smart')}>
        <div className="brand-icon-wrapper">
          <Shield size={20} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="brand-title">RealityChecker</span>
            <span className="brand-badge">PRO v1.2</span>
          </div>
        </div>
      </div>

      <nav className="nav-tabs">
        <button
          className={`nav-tab-btn ${currentTab === 'smart' ? 'active' : ''}`}
          onClick={() => onTabChange('smart')}
        >
          <Sparkles size={16} />
          智能同ASN推荐
        </button>
        <button
          className={`nav-tab-btn ${currentTab === 'assets' ? 'active' : ''}`}
          onClick={() => onTabChange('assets')}
        >
          <Database size={16} />
          资产全量管理
        </button>
        <button
          className={`nav-tab-btn ${currentTab === 'asns' ? 'active' : ''}`}
          onClick={() => onTabChange('asns')}
        >
          <Globe2 size={16} />
          全球 ASN 拓扑
        </button>
        <button
          className={`nav-tab-btn ${currentTab === 'stats' ? 'active' : ''}`}
          onClick={() => onTabChange('stats')}
        >
          <BarChart3 size={16} />
          数据分析概览
        </button>
      </nav>

      <div className="nav-actions">
        <div className="status-indicator">
          <span
            className="pulse-dot"
            style={{
              background: serviceOnline ? 'var(--accent-emerald)' : 'var(--accent-rose)',
              boxShadow: serviceOnline
                ? '0 0 10px var(--accent-emerald)'
                : '0 0 10px var(--accent-rose)',
            }}
          />
          <span>{serviceOnline ? '后端引擎运行中' : '连接中断'}</span>
        </div>
        <button className="btn-icon" title="刷新数据" onClick={onRefreshStats}>
          <RefreshCw size={16} />
        </button>
      </div>
    </header>
  );
};

import { useEffect, useState } from 'react';
import type { TargetStats } from '../types';
import { Database, ShieldCheck, Zap, Globe, Star } from 'lucide-react';

export const StatsDashboard = () => {
  const [stats, setStats] = useState<TargetStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/stats')
      .then((res) => res.json())
      .then((data) => {
        if (data.code === 200) {
          setStats(data.data);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
        正在拉取全局指标...
      </div>
    );
  }

  if (!stats) return null;

  const activeRate = stats.total_targets > 0 ? Math.round((stats.active_targets / stats.total_targets) * 100) : 0;
  const fiveStarRate = stats.total_targets > 0 ? Math.round((stats.five_star_targets / stats.total_targets) * 100) : 0;

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>资产多维统计指标</h2>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          SQLite 持久化数据全貌监控 · 涵盖 ASN 自治域分布、握手延迟基线与存活健康度
        </p>
      </div>

      {/* 顶部指标卡片 */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(56, 189, 248, 0.15)', color: 'var(--accent-cyan)' }}>
            <Database size={24} />
          </div>
          <div>
            <div className="stat-val">{stats.total_targets}</div>
            <div className="stat-name">收录资产总数</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(16, 185, 129, 0.15)', color: 'var(--accent-emerald)' }}>
            <ShieldCheck size={24} />
          </div>
          <div>
            <div className="stat-val">{activeRate}%</div>
            <div className="stat-name">存活健康率 ({stats.active_targets} 个活跃)</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(251, 146, 60, 0.15)', color: 'var(--accent-fire)' }}>
            <Globe size={24} />
          </div>
          <div>
            <div className="stat-val">{stats.total_asns}</div>
            <div className="stat-name">覆盖 ASN 自治域数</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(245, 158, 11, 0.15)', color: 'var(--accent-amber)' }}>
            <Star size={24} />
          </div>
          <div>
            <div className="stat-val">{fiveStarRate}%</div>
            <div className="stat-name">5 星极品率 ({stats.five_star_targets} 个)</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon" style={{ background: 'rgba(192, 132, 252, 0.15)', color: 'var(--accent-purple)' }}>
            <Zap size={24} />
          </div>
          <div>
            <div className="stat-val">{stats.avg_handshake_ms} ms</div>
            <div className="stat-name">平均 TLS 握手延迟</div>
          </div>
        </div>
      </div>

      {/* 分布视图 */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '20px' }}>
        {/* 国家分布 */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '1.1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Globe size={18} style={{ color: 'var(--accent-cyan)' }} />
            国家 / 地区资产分布 (Top 20)
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {Object.entries(stats.country_counts).map(([country, count]) => {
              const pct = stats.total_targets > 0 ? (count / stats.total_targets) * 100 : 0;
              return (
                <div key={country}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
                    <span style={{ fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{country || 'OTHER'}</span>
                    <span style={{ color: 'var(--text-muted)' }}>{count} 个 ({pct.toFixed(1)}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        background: 'linear-gradient(90deg, #38bdf8, #2563eb)',
                        borderRadius: '3px',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* 星级梯队 */}
        <div className="glass-panel" style={{ padding: '24px' }}>
          <h3 style={{ fontSize: '1.1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Star size={18} style={{ color: 'var(--accent-amber)' }} />
            星级评分梯队分布
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {[5, 4, 3, 2, 1, 0].map((star) => {
              const count = stats.star_counts[star.toString()] || 0;
              const pct = stats.total_targets > 0 ? (count / stats.total_targets) * 100 : 0;
              return (
                <div key={star}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '4px' }}>
                    <span style={{ color: '#fbbf24' }}>
                      {star > 0 ? '★'.repeat(star) + ` (${star} 星)` : '未评级 / 基础'}
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>{count} 个 ({pct.toFixed(1)}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div
                      style={{
                        width: `${pct}%`,
                        height: '100%',
                        background: star >= 5 ? 'linear-gradient(90deg, #fbbf24, #f59e0b)' : 'linear-gradient(90deg, #38bdf8, #818cf8)',
                        borderRadius: '3px',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

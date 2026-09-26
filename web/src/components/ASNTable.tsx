import { useState, useEffect } from 'react';
import type { ASNRecord } from '../types';
import { RefreshCw, CheckCircle, Clock, Loader2 } from 'lucide-react';

export const ASNTable = () => {
  const [asns, setAsns] = useState<ASNRecord[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchASNs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/asns?limit=100');
      const data = await res.json();
      if (res.ok && data.code === 200) {
        setAsns(data.data || []);
      }
    } catch (err) {
      console.error('Failed to load ASNs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchASNs();
  }, []);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 800 }}>全球 ASN 自治系统雷达</h2>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            全球骨干网络任务登记册 · 追踪各自治域的扫描状态、IP 资产储备与成功命中率
          </p>
        </div>

        <button className="btn btn-secondary" onClick={fetchASNs}>
          <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
          刷新列表
        </button>
      </div>

      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>ASN 编号</th>
              <th>自治域名称 (Name)</th>
              <th>归属国家</th>
              <th>总 IP 估算</th>
              <th>调度优先级</th>
              <th>扫描状态</th>
              <th>成功命中数</th>
              <th>最后探测时间</th>
            </tr>
          </thead>
          <tbody>
            {asns.map((row) => (
              <tr key={row.asn}>
                <td>
                  <span className="badge badge-same-asn" style={{ fontWeight: 700 }}>
                    AS{row.asn}
                  </span>
                </td>
                <td style={{ fontWeight: 600 }}>{row.name || 'Autonomous System'}</td>
                <td>
                  <span className="badge badge-global">{row.country || 'N/A'}</span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>
                  {row.total_ips > 0 ? row.total_ips.toLocaleString() : '-'}
                </td>
                <td>
                  <span className="badge badge-warning" style={{ fontFamily: 'var(--font-mono)' }}>
                    P{row.priority}
                  </span>
                </td>
                <td>
                  {row.scan_status === 'completed' ? (
                    <span className="badge badge-success">
                      <CheckCircle size={12} /> 已完成
                    </span>
                  ) : row.scan_status === 'scanning' ? (
                    <span className="badge badge-same-country">
                      <Loader2 size={12} className="animate-spin" /> 探测中
                    </span>
                  ) : (
                    <span className="badge badge-global">
                      <Clock size={12} /> 待命
                    </span>
                  )}
                </td>
                <td>
                  <span style={{ fontWeight: 700, color: 'var(--accent-emerald)', fontFamily: 'var(--font-mono)' }}>
                    {row.success_target_count} 个
                  </span>
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-sub)' }}>
                  {row.last_scanned_at ? new Date(row.last_scanned_at).toLocaleString() : '未扫描'}
                </td>
              </tr>
            ))}

            {asns.length === 0 && !loading && (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-sub)' }}>
                  暂未登记 ASN 数据记录（可在终端运行 <code>reality-checker daemon</code> 自动建立）
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

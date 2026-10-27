import { useState, useEffect } from 'react';
import type { RankedTargetItem, TargetItem, TargetRecord } from '../types';
import { recheckTarget } from '../api';
import { formatCertExpireDate } from '../format';
import {
  X,
  Copy,
  Check,
  ExternalLink,
  Zap,
  ShieldCheck,
  Globe,
  Clock,
  Calendar,
  Server,
  Flame,
  FileText,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
} from 'lucide-react';

interface TargetDetailModalProps {
  target: RankedTargetItem | TargetItem | null;
  onClose: () => void;
  onOpenConfig?: (target: TargetItem) => void;
  onRecheck?: (target: TargetRecord) => void;
}

export const TargetDetailModal = ({ target, onClose, onOpenConfig, onRecheck }: TargetDetailModalProps) => {
  const [copied, setCopied] = useState(false);
  const [rechecking, setRechecking] = useState(false);
  const [recheckError, setRecheckError] = useState('');
  const [recheckSuccess, setRecheckSuccess] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!target) return null;

  const copyDomain = (domain: string) => {
    navigator.clipboard.writeText(domain);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const openDomainUrl = (domain: string) => {
    window.open(`https://${domain}`, '_blank', 'noopener,noreferrer');
  };

  const handleRecheck = async () => {
    if (!target || !onRecheck || rechecking) return;

    setRechecking(true);
    setRecheckError('');
    setRecheckSuccess(false);
    try {
      const updated = await recheckTarget(target.domain, target.ip);
      onRecheck(updated);
      setRecheckSuccess(true);
    } catch (err) {
      setRecheckError(err instanceof Error ? err.message : '目标复检失败');
    } finally {
      setRechecking(false);
    }
  };

  const isRanked = 'match_level' in target;
  const matchLevel = isRanked ? (target as RankedTargetItem).match_level : undefined;
  const score = isRanked ? (target as RankedTargetItem).score : undefined;

  const certStatus =
    target.cert_days > 30
      ? { label: '证书稳定充裕', badgeClass: 'badge-success', icon: CheckCircle2 }
      : target.cert_days > 0
      ? { label: '证书临期 (≤30天)', badgeClass: 'badge-warning', icon: AlertTriangle }
      : { label: '证书已过期', badgeClass: 'badge-danger', icon: AlertTriangle };

  const CertIcon = certStatus.icon;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content detail-modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '720px' }}
      >
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: 'var(--radius-md)',
                background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.25), rgba(37, 99, 235, 0.35))',
                border: '1px solid rgba(56, 189, 248, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--accent-cyan)',
              }}
            >
              <ShieldCheck size={20} />
            </div>
            <div>
              <h3 className="modal-title" style={{ fontSize: '1.2rem', margin: 0 }}>
                目标资产详细信息
              </h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-sub)', margin: 0 }}>
                REALITY 伪装域名全链路技术指标与证书状态
              </p>
            </div>
          </div>

          <button
            type="button"
            className="btn-icon"
            onClick={onClose}
            style={{ padding: '6px', borderRadius: 'var(--radius-sm)' }}
            title="关闭 (Esc)"
          >
            <X size={18} />
          </button>
        </div>

        {/* 核心指标卡片：域名、标题、证书剩余时间、到期时间 */}
        <div className="detail-cards-grid">
          {/* 1. 域名 */}
          <div className="detail-card detail-card-hero">
            <div className="detail-card-label">
              <Globe size={14} style={{ color: 'var(--accent-cyan)' }} />
              <span>伪装域名 (Domain)</span>
            </div>
            <div className="detail-domain-row">
              <span className="detail-domain-text">{target.domain}</span>
              <div className="detail-domain-actions">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => copyDomain(target.domain)}
                  title="复制域名"
                >
                  {copied ? <Check size={13} style={{ color: 'var(--accent-emerald)' }} /> : <Copy size={13} />}
                  <span>{copied ? '已复制' : '复制'}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm btn-open-web"
                  onClick={() => openDomainUrl(target.domain)}
                  title="在新标签页直接打开域名网页"
                >
                  <ExternalLink size={13} style={{ color: 'var(--accent-cyan)' }} />
                  <span>打开网页</span>
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap', marginTop: '8px' }}>
              {matchLevel === 'same_asn' ? (
                <span className="badge badge-same-asn">
                  <Flame size={12} /> 同 ASN 极速直连
                </span>
              ) : matchLevel === 'same_country' ? (
                <span className="badge badge-same-country">
                  <Globe size={12} /> 同国家骨干
                </span>
              ) : (
                <span className="badge badge-global">全球精选</span>
              )}

              <span className="star-rating">{'★'.repeat(target.stars)}</span>
              {target.is_starred && <span className="badge badge-warning">已收藏</span>}

              {score !== undefined && (
                <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
                  匹配分: {score}
                </span>
              )}
            </div>
          </div>

          {/* 2. 网站页面标题 */}
          <div className="detail-card detail-card-full">
            <div className="detail-card-label">
              <FileText size={14} style={{ color: 'var(--accent-amber)' }} />
              <span>网站标题 (Title)</span>
            </div>
            <div
              className="detail-title-text"
              style={{
                fontSize: '0.92rem',
                color: target.page_title ? 'var(--text-main)' : 'var(--text-sub)',
                fontStyle: target.page_title ? 'normal' : 'italic',
                wordBreak: 'break-word',
                lineHeight: 1.5,
              }}
            >
              {target.page_title || '（未获取到网页标题 / 443 协议直通服务）'}
            </div>
          </div>

          {/* 3. 证书剩余时间 */}
          <div className="detail-card">
            <div className="detail-card-label">
              <Clock size={14} style={{ color: 'var(--accent-emerald)' }} />
              <span>证书剩余时间</span>
            </div>
            <div className="detail-highlight-val">
              <span
                style={{
                  fontSize: '1.4rem',
                  fontWeight: 800,
                  fontFamily: 'var(--font-mono)',
                  color:
                    target.cert_days <= 0
                      ? 'var(--accent-rose)'
                      : target.cert_days < 30
                      ? 'var(--accent-amber)'
                      : 'var(--accent-emerald)',
                }}
              >
                {target.cert_days <= 0 ? '已过期' : `${target.cert_days} 天`}
              </span>
              <span className={`badge ${certStatus.badgeClass}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                <CertIcon size={12} />
                {certStatus.label}
              </span>
            </div>
          </div>

          {/* 4. 证书到期时间 */}
          <div className="detail-card">
            <div className="detail-card-label">
              <Calendar size={14} style={{ color: 'var(--accent-fire)' }} />
              <span>到期时间 (Expiration)</span>
            </div>
            <div
              className="detail-highlight-val"
              style={{
                fontSize: '0.98rem',
                fontWeight: 600,
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-main)',
              }}
            >
              {formatCertExpireDate(target.cert_expire_at, target.cert_days)}
            </div>
          </div>
        </div>

        {/* 进阶网络与协议指标 */}
        <div className="detail-specs-box">
          <div className="spec-item">
            <span className="spec-label">TLS 握手延时</span>
            <span
              className="spec-value font-mono"
              style={{
                color:
                  target.handshake_ms < 60
                    ? 'var(--accent-emerald)'
                    : target.handshake_ms < 150
                    ? 'var(--accent-cyan)'
                    : target.handshake_ms < 250
                    ? 'var(--accent-amber)'
                    : 'var(--text-main)',
              }}
            >
              {target.handshake_ms} ms
            </span>
          </div>

          <div className="spec-item">
            <span className="spec-label" style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <Server size={12} style={{ color: 'var(--accent-fire)' }} />
              <span>所属 ASN / 地区</span>
            </span>
            <span className="spec-value">
              {target.asn || '未知'} ({target.country || 'N/A'})
            </span>
          </div>

          <div className="spec-item">
            <span className="spec-label">解析 IP</span>
            <span className="spec-value font-mono">{target.ip || '直连解析'}</span>
          </div>

          <div className="spec-item">
            <span className="spec-label">HTTP 状态</span>
            <span className="spec-value">
              {target.status_code > 0 ? (
                <span style={{ color: target.status_code < 400 ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                  {target.status_code} OK
                </span>
              ) : (
                '443 直通'
              )}
            </span>
          </div>
        </div>

        {/* 协议与伪装特征标签 */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          <span className="badge badge-success">TLS 1.3</span>
          <span className="badge badge-success">X25519</span>
          <span className="badge badge-success">H2</span>
          {!target.is_cdn && <span className="badge badge-global">源站直连 (无 CDN)</span>}
          {target.tags?.includes('cert_renew_delayed') && (
            <span className="badge badge-warning" title="证书剩余不足30天且尚未自动续期">
              疑似未自动续期
            </span>
          )}
          {target.is_default_page && (
            <span className="badge badge-warning">{target.default_page_type || 'Nginx'} 默认页</span>
          )}
        </div>

        {/* Footer 操作按钮 */}
        <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', alignItems: 'flex-start' }}>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={() => openDomainUrl(target.domain)}
            >
              <ExternalLink size={14} style={{ color: 'var(--accent-cyan)' }} />
              <span>在新标签打开网页</span>
            </button>
            {recheckError && <span style={{ color: 'var(--accent-rose)', fontSize: '0.78rem' }}>{recheckError}</span>}
            {recheckSuccess && <span style={{ color: 'var(--accent-emerald)', fontSize: '0.78rem' }}>✓ 复检完成，数据已更新</span>}
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            {onRecheck && (
              <button
                type="button"
                className="btn btn-secondary"
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                onClick={handleRecheck}
                disabled={rechecking}
              >
                <RefreshCw size={14} className={rechecking ? 'animate-spin' : ''} />
                <span>{rechecking ? '复检中...' : '复检'}</span>
              </button>
            )}
            {onOpenConfig && (
              <button
                type="button"
                className="btn btn-primary"
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                onClick={() => {
                  onClose();
                  onOpenConfig(target);
                }}
              >
                <Zap size={14} />
                <span>一键生成配置</span>
              </button>
            )}

            <button type="button" className="btn btn-secondary" onClick={onClose}>
              关闭
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

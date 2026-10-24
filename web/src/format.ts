/**
 * 格式化证书到期时间
 * @param expireAt ISO 时间字符串
 * @param certDays 证书剩余天数
 */
export function formatCertExpireDate(expireAt?: string, certDays?: number): string {
  if (expireAt && expireAt !== '0001-01-01T00:00:00Z') {
    const d = new Date(expireAt);
    if (!isNaN(d.getTime())) {
      return d.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
    }
  }
  if (certDays !== undefined && certDays > 0) {
    const d = new Date(Date.now() + certDays * 86400000);
    return `约 ${d.toLocaleDateString('zh-CN')} (按剩余天数推算)`;
  }
  return '未知或已过期';
}

/**
 * ISO 3166-1 alpha-2 常用国家/地区顶级域名映射
 * 绝大部分国家的 ccTLD 与其 2 位国家代码一致（小写），部分特殊地区如 GB/UK 提供映射
 */
const COUNTRY_CCTLD_MAP: Record<string, string> = {
  GB: 'uk', // 英国顶级域名主要为 .uk
  UK: 'uk',
};

/**
 * 根据国家代码获取对应的国家/地区域名后缀（如 "US" -> ".us", "CN" -> ".cn"）
 * @param countryCode ISO 国家代码或国家名称
 */
export function getCountryDomainSuffix(countryCode?: string): string | null {
  if (!countryCode) return null;
  const clean = countryCode.trim().toUpperCase();
  if (!clean || clean === 'GLOBAL' || clean === 'N/A' || clean === 'UNKNOWN') return null;

  // 如果已经是两位字母的国家代码
  if (/^[A-Z]{2}$/.test(clean)) {
    const sfx = COUNTRY_CCTLD_MAP[clean] || clean.toLowerCase();
    return `.${sfx}`;
  }

  return null;
}

/**
 * 将 2 位 ISO 国家代码转换为 Emoji 国旗
 * @param countryCode 两位 ISO 国家代码，例如 "US", "JP", "CN"
 */
export function getCountryFlagEmoji(countryCode?: string): string {
  if (!countryCode) return '';
  const clean = countryCode.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(clean)) return '';

  const offset = 127397;
  try {
    return String.fromCodePoint(...clean.split('').map((c) => c.charCodeAt(0) + offset));
  } catch {
    return '';
  }
}

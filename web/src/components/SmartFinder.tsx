import { useState, useRef, useEffect, useMemo, Fragment } from 'react';
import type {
  RankedTargetItem,
  TargetSummaryInfo,
  TargetItem,
  SmartFilterOptions,
  ScanProgressInfo,
} from '../types';
import { ConfigModal } from './ConfigModal';
import { TargetDetailModal } from './TargetDetailModal';
import { formatCertExpireDate } from '../format';
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
  Filter,
  SlidersHorizontal,
  RotateCcw,
  Search,
  X,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Clock,
  Calendar,
  FileText,
  LayoutGrid,
  List,
  ExternalLink,
  Info,
} from 'lucide-react';

const DEFAULT_FILTER: SmartFilterOptions = {
  minStars: 3,
  maxHandshakeMS: 0,
  requireNoCDN: true,
  requireNoDefaultPage: false,
  requireNoCN: true,
  minCertDays: 0,
  matchScope: 'all',
  statusFilter: 'all',
  keyword: '',
  domainSuffixes: '',
};

export const SmartFinder = () => {
  const [ip, setIP] = useState('');

  // 过滤器状态（完全由前端控制，支持即时响应与热切换）
  const [filter, setFilter] = useState<SmartFilterOptions>(DEFAULT_FILTER);
  const [showAdvancedFilter, setShowAdvancedFilter] = useState(false);

  // 鉴权 Token
  const [apiToken, setApiToken] = useState(() => localStorage.getItem('rc_api_token') || '');
  const [showTokenSettings, setShowTokenSettings] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [summary, setSummary] = useState<TargetSummaryInfo | null>(null);

  // 原始所有召回目标资产池 (数据库返回 + 实时扫描推流)，前端按过滤器纯函数派生最终渲染列表
  const [rawTargets, setRawTargets] = useState<RankedTargetItem[]>([]);

  // 实时扫描进度同步状态
  const [scanProgress, setScanProgress] = useState<ScanProgressInfo>({
    isScanning: false,
    scannedIPs: 0,
    totalIPs: 0,
    currentCIDR: '',
    currentIP: '',
    speed: 0,
    percent: 0,
    foundCount: 0,
    matchedCount: 0,
    message: '',
  });

  // 最近一次新发现的目标（用于高亮动画反馈）
  const [latestDiscoveredDomain, setLatestDiscoveredDomain] = useState<string | null>(null);

  const [selectedTarget, setSelectedTarget] = useState<TargetItem | null>(null);
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  // 布局视图模式：'grid' 为卡片网格，'list' 为列表视图
  const [viewMode, setViewMode] = useState<'grid' | 'list'>(() => {
    return (localStorage.getItem('rc_targets_view_mode') as 'grid' | 'list') || 'grid';
  });

  // 详细信息弹窗选中的目标
  const [selectedDetailTarget, setSelectedDetailTarget] = useState<RankedTargetItem | null>(null);

  // 列表视图中行内折叠/展开的域名集合
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set());

  const handleViewModeChange = (mode: 'grid' | 'list') => {
    setViewMode(mode);
    localStorage.setItem('rc_targets_view_mode', mode);
  };

  const toggleExpandDomain = (domain: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setExpandedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) {
        next.delete(domain);
      } else {
        next.add(domain);
      }
      return next;
    });
  };

  const openDomainUrl = (domain: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    window.open(`https://${domain}`, '_blank', 'noopener,noreferrer');
  };

  // Refs 维护实时最新的状态，避免闭包捕获陈旧值
  const esRef = useRef<EventSource | null>(null);
  const summaryRef = useRef<TargetSummaryInfo | null>(null);
  const filterRef = useRef<SmartFilterOptions>(filter);
  const scanMetricsRef = useRef<{
    startTime: number;
    lastTime: number;
    lastCount: number;
  }>({ startTime: 0, lastTime: 0, lastCount: 0 });

  useEffect(() => {
    summaryRef.current = summary;
  }, [summary]);

  useEffect(() => {
    filterRef.current = filter;
  }, [filter]);

  // 初始化加载服务端推荐过滤器默认值
  useEffect(() => {
    fetch('/api/filter/default')
      .then((res) => res.json())
      .then((data) => {
        if (data.code === 200 && data.data) {
          setFilter((prev) => ({
            ...prev,
            minStars: data.data.min_stars !== undefined && data.data.min_stars > 0 ? data.data.min_stars : prev.minStars,
            requireNoCN: data.data.require_no_cn !== undefined ? !!data.data.require_no_cn : prev.requireNoCN,
            requireNoCDN: data.data.require_no_cdn !== undefined ? !!data.data.require_no_cdn : prev.requireNoCDN,
            requireNoDefaultPage: data.data.require_no_default_page !== undefined ? !!data.data.require_no_default_page : prev.requireNoDefaultPage,
            maxHandshakeMS: data.data.max_handshake_ms !== undefined ? data.data.max_handshake_ms : prev.maxHandshakeMS,
            minCertDays: data.data.min_cert_days !== undefined ? data.data.min_cert_days : prev.minCertDays,
          }));
        }
      })
      .catch(() => {});

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

  // 快捷测试 IP 资产
  const sampleIPs = [
    { label: '东京 Vultr (AS20473)', ip: '45.76.12.34' },
    { label: '新加坡 Linode (AS63949)', ip: '139.162.24.12' },
    { label: '美国 Oracle (AS31898)', ip: '140.238.10.55' },
    { label: '香港 GCP (AS396982)', ip: '34.92.12.80' },
  ];

  // 前端过滤核心匹配函数 (纯函数，0 延迟即时评估)
  const isItemMatchFilter = (
    item: TargetItem | RankedTargetItem,
    f: SmartFilterOptions,
    currSummary?: TargetSummaryInfo | null
  ): boolean => {
    // 1. 最低星级限制
    if (f.minStars > 0 && item.stars < f.minStars) return false;

    // 2. 最大握手延迟限制
    if (f.maxHandshakeMS > 0 && item.handshake_ms > f.maxHandshakeMS) return false;

    // 3. 源站直连 / 排除 CDN
    if (f.requireNoCDN && item.is_cdn) return false;

    // 4. 排除 Nginx / 默认页面
    if (f.requireNoDefaultPage && item.is_default_page) return false;

    // 5. 排除 .cn / 境内后缀域名
    if (f.requireNoCN) {
      const d = item.domain.toLowerCase();
      if (d.endsWith('.cn') || d.includes('.edu.cn') || d.includes('.gov.cn')) return false;
    }

    // 6. 证书剩余有效天数
    if (f.minCertDays > 0 && item.cert_days < f.minCertDays) return false;

    // 7. 匹配范畴范围过滤
    const targetASN = currSummary?.asn?.toUpperCase().replace(/^AS/, '');
    const itemASN = item.asn?.toUpperCase().replace(/^AS/, '');
    const isSameASN = !!(targetASN && itemASN && targetASN === itemASN);

    const targetCountry = currSummary?.country?.toUpperCase();
    const itemCountry = item.country?.toUpperCase();
    const isSameCountry = !!(targetCountry && itemCountry && targetCountry === itemCountry);

    if (f.matchScope === 'same_asn' && !isSameASN) return false;
    if (f.matchScope === 'same_country' && !isSameASN && !isSameCountry) return false;

    // 8. HTTP 状态码校验 (仅 200 OK 或 443 直出)
    if (f.statusFilter === 'success_only') {
      if (item.status_code >= 400 || (item.status_code < 200 && item.status_code !== 0)) return false;
    }

    // 9. 域名或网站标题即时关键词筛选
    if (f.keyword.trim()) {
      const kw = f.keyword.trim().toLowerCase();
      const inDomain = item.domain.toLowerCase().includes(kw);
      const inTitle = item.page_title ? item.page_title.toLowerCase().includes(kw) : false;
      const inASN = item.asn ? item.asn.toLowerCase().includes(kw) : false;
      if (!inDomain && !inTitle && !inASN) return false;
    }

    // 10. 域名后缀过滤 (支持逗号分隔多个，如 .com, .net, .org)
    if (f.domainSuffixes && f.domainSuffixes.trim()) {
      const suffixes = f.domainSuffixes
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
        .map((s) => (s.startsWith('.') ? s : `.${s}`));
      if (suffixes.length > 0) {
        const domainLower = item.domain.toLowerCase();
        const matchAny = suffixes.some((sfx) => domainLower.endsWith(sfx));
        if (!matchAny) return false;
      }
    }

    return true;
  };

  // 纯前端响应式计算当前展示的目标清单（即时响应，零网络开销）
  const displayedTargets = useMemo(() => {
    return rawTargets.filter((item) => isItemMatchFilter(item, filter, summary));
  }, [rawTargets, filter, summary]);

  // 统计已激活的高级过滤器数量
  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (filter.minStars > 0) count++;
    if (filter.maxHandshakeMS > 0) count++;
    if (filter.requireNoCDN) count++;
    if (filter.requireNoDefaultPage) count++;
    if (filter.requireNoCN) count++;
    if (filter.minCertDays > 0) count++;
    if (filter.matchScope !== 'all') count++;
    if (filter.statusFilter !== 'all') count++;
    if (filter.keyword.trim()) count++;
    if (filter.domainSuffixes && filter.domainSuffixes.trim()) count++;
    return count;
  }, [filter]);

  // 检查某个域名后缀是否已在当前筛选列表中
  const isSuffixSelected = (sfx: string): boolean => {
    if (!filter.domainSuffixes || !filter.domainSuffixes.trim()) return false;
    const clean = sfx.trim().toLowerCase().startsWith('.') ? sfx.trim().toLowerCase() : `.${sfx.trim().toLowerCase()}`;
    const list = filter.domainSuffixes
      .split(',')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
      .map((s) => (s.startsWith('.') ? s : `.${s}`));
    return list.includes(clean);
  };

  // 快速切换 / 添加 / 移除域名后缀
  const toggleSuffix = (sfx: string) => {
    setFilter((prev) => {
      const clean = sfx.trim().toLowerCase().startsWith('.') ? sfx.trim().toLowerCase() : `.${sfx.trim().toLowerCase()}`;
      const list = prev.domainSuffixes
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
        .map((s) => (s.startsWith('.') ? s : `.${s}`));

      let newList: string[];
      if (list.includes(clean)) {
        newList = list.filter((item) => item !== clean);
      } else {
        newList = [...list, clean];
      }
      return {
        ...prev,
        domainSuffixes: newList.join(', '),
      };
    });
  };

  // 重置所有过滤器
  const resetFilters = () => {
    setFilter({
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
    });
  };

  // 应用推荐过滤器配置
  const applyRecommendedFilters = () => {
    setFilter({
      minStars: 3,
      maxHandshakeMS: 150,
      requireNoCDN: true,
      requireNoDefaultPage: true,
      requireNoCN: true,
      minCertDays: 15,
      matchScope: 'all',
      statusFilter: 'all',
      keyword: '',
      domainSuffixes: '.com',
    });
  };

  // 终止流式扫描
  const stopScan = () => {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    setScanProgress((prev) => ({
      ...prev,
      isScanning: false,
      message: `⏹ 扫描已由用户手动停止，当前探测断点已安全归档入库。`,
    }));
  };

  // 核心查询逻辑：优先从库里匹配目标，同时提取目标 IP 的 ASN 与网络拓扑元数据
  const handleSearch = async (e?: React.FormEvent, customIP?: string) => {
    if (e) e.preventDefault();
    const cleanIP = (customIP !== undefined ? customIP : ip).trim();
    if (!cleanIP) {
      setError('请输入节点服务器 IP');
      return;
    }

    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }

    setScanProgress((prev) => ({ ...prev, isScanning: false }));
    setLoading(true);
    setError('');
    setRawTargets([]);

    try {
      const tokenParam = apiToken.trim() ? `&token=${encodeURIComponent(apiToken.trim())}` : '';
      // 请求大容量候选池 (limit=100)，方便前端过滤器实时筛选与切换
      const url = `/api/targets/smart?ip=${encodeURIComponent(cleanIP)}&limit=100&min_stars=1&require_no_cn=0${tokenParam}`;

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
      setRawTargets(data.data.targets || []);
      setScanProgress((prev) => ({
        ...prev,
        isScanning: false,
        message: '',
      }));
    } catch (err: any) {
      setError(err.message || '网络连接异常');
    } finally {
      setLoading(false);
    }
  };

  // 启动实时扫描：实时同步扫描进度，有新的符合过滤器的结果立即返回与渲染
  const startScanStream = (scanAll: boolean = true) => {
    const cleanIP = ip.trim();
    if (!cleanIP) {
      setError('请输入节点服务器 IP');
      return;
    }

    if (esRef.current) {
      esRef.current.close();
    }

    const now = Date.now();
    scanMetricsRef.current = {
      startTime: now,
      lastTime: now,
      lastCount: 0,
    };

    setScanProgress({
      isScanning: true,
      scannedIPs: 0,
      totalIPs: summary?.total_ips || 0,
      currentCIDR: '',
      currentIP: '',
      speed: 0,
      percent: 0,
      foundCount: 0,
      matchedCount: 0,
      message: '正在建立流式探测长连接通道，提前同步目标 ASN 拓扑元数据...',
    });
    setError('');

    const tokenParam = apiToken.trim() ? `&token=${encodeURIComponent(apiToken.trim())}` : '';
    const scanAllParam = scanAll ? '&scan_all=1' : '';
    const url = `/api/targets/stream?ip=${encodeURIComponent(cleanIP)}&limit=50&min_stars=1&require_no_cn=0${scanAllParam}${tokenParam}`;

    const es = new EventSource(url);
    esRef.current = es;

    // 1. 初始化事件: 首帧同步 ASN 拓扑与断点信息
    es.addEventListener('init', (evt: any) => {
      try {
        const data = JSON.parse(evt.data);
        const updatedSummary: TargetSummaryInfo = {
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
          total_hits: data.cached_hits,
        };
        setSummary(updatedSummary);
        summaryRef.current = updatedSummary;

        let msg = `⚡ 拓扑就绪：${data.asn} (${data.country}) · ${data.is_residential ? '家庭宽带' : '机房数据中心'}`;
        if (data.cidr_count) {
          msg += `，共 ${data.cidr_count} 个网段 (约 ${data.total_ips?.toLocaleString() || 0} 个 IP)`;
        }
        if (data.has_checkpoint && data.last_checkpoint_ip) {
          msg += `，发现断点，正从 ${data.last_checkpoint_ip} 自动精准续传...`;
        } else {
          msg += `，正在开启全并发流水线探测...`;
        }

        setScanProgress((prev) => ({
          ...prev,
          totalIPs: data.total_ips || prev.totalIPs,
          message: msg,
        }));
      } catch (_) {}
    });

    // 2. 进度同步事件: 实时计算扫描进度与速率
    es.addEventListener('progress', (evt: any) => {
      try {
        const data = JSON.parse(evt.data);
        const currentScanned = Number(data.scanned_ips) || 0;
        const nowMs = Date.now();
        const elapsedSec = (nowMs - scanMetricsRef.current.startTime) / 1000;
        const speed = elapsedSec > 0 ? Math.round(currentScanned / elapsedSec) : 0;

        setScanProgress((prev) => {
          const tot = prev.totalIPs > 0 ? prev.totalIPs : summaryRef.current?.total_ips || 0;
          const pct = tot > 0 ? Math.min(100, Math.round((currentScanned / tot) * 100)) : 0;
          return {
            ...prev,
            scannedIPs: currentScanned,
            currentCIDR: data.current_cidr || prev.currentCIDR,
            currentIP: data.current_ip || prev.currentIP,
            speed: speed > 0 ? speed : prev.speed,
            percent: pct,
          };
        });
      } catch (_) {}
    });

    // 3. 目标发现事件: 有新的符合过滤器的结果立即返回并渲染！
    es.addEventListener('target', (evt: any) => {
      try {
        const item: TargetItem = JSON.parse(evt.data);
        const activeSummary = summaryRef.current;
        const targetASNNorm = activeSummary?.asn?.toUpperCase().replace(/^AS/, '');
        const itemASNNorm = item.asn?.toUpperCase().replace(/^AS/, '');
        const isSameASN = !!(targetASNNorm && itemASNNorm && targetASNNorm === itemASNNorm);
        const isSameCountry = !!(activeSummary?.country && item.country && activeSummary.country.toUpperCase() === item.country.toUpperCase());

        const ranked: RankedTargetItem = {
          ...item,
          match_level: isSameASN ? 'same_asn' : isSameCountry ? 'same_country' : 'global',
          score: isSameASN ? 1000 + item.stars * 30 : isSameCountry ? 250 + item.stars * 30 : 50 + item.stars * 30,
          is_new_scan: true,
        };

        // 检查是否符合当前前端激活的过滤器
        const matchesCurrentFilter = isItemMatchFilter(ranked, filterRef.current, activeSummary);

        // 立即存入原始池，并置顶于列表最前方
        setRawTargets((prev) => {
          const exists = prev.some((p) => p.domain === item.domain);
          if (exists) return prev;
          return [ranked, ...prev];
        });

        if (matchesCurrentFilter) {
          setLatestDiscoveredDomain(item.domain);
          // 4 秒后清除新发现的高亮状态
          setTimeout(() => setLatestDiscoveredDomain(null), 4000);
        }

        // 同步累计发现数与符合过滤器的匹配数
        setScanProgress((prev) => ({
          ...prev,
          foundCount: prev.foundCount + 1,
          matchedCount: matchesCurrentFilter ? prev.matchedCount + 1 : prev.matchedCount,
          message: matchesCurrentFilter
            ? `✨ 实时新发现符合目标: ${item.domain} (${item.stars}★, ${item.handshake_ms}ms)`
            : `🔎 扫描命中新资产: ${item.domain} (未通过当前过滤器，已收录资产库)`,
        }));
      } catch (_) {}
    });

    // 4. 完成事件
    es.addEventListener('done', (evt: any) => {
      let totalFound = 0;
      try {
        const doneData = JSON.parse(evt.data);
        totalFound = doneData.total_found || 0;
      } catch (_) {}

      setScanProgress((prev) => ({
        ...prev,
        isScanning: false,
        percent: 100,
        message: `✅ 实时扫描已全部完成！共探测发现 ${totalFound || prev.foundCount} 个资产，当前展示 ${prev.matchedCount} 个符合过滤标准的目标。`,
      }));

      es.close();
      esRef.current = null;
    });

    // 5. 异常或中断事件
    es.addEventListener('error', () => {
      setScanProgress((prev) => ({
        ...prev,
        isScanning: false,
        message: prev.foundCount > 0 ? `⚠️ 流式探测已断开，已安全保存已发现的 ${prev.foundCount} 个资产。` : '',
      }));
      es.close();
      esRef.current = null;
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
              输入你的落地服务器或 VPS IP，从资产库秒级匹配。
              <b style={{ color: '#fb923c' }}> 支持前端实时多维过滤；启动实时扫描时同步进度，有新符合结果立即返回。</b>
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

        {/* 核心检索卡片 */}
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

            <button type="submit" className="btn btn-primary" disabled={loading || scanProgress.isScanning}>
              {loading ? <Radio size={16} className="animate-spin" /> : <Sparkles size={16} />}
              {loading ? '正在匹配...' : '匹配资产库'}
            </button>
          </form>

          {/* 快捷填入示例 IP */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '14px', flexWrap: 'wrap', gap: '10px' }}>
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
                    handleSearch(undefined, s.ip);
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {/* 快速重置 / 高级过滤展开入口 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                className={`btn ${showAdvancedFilter ? 'btn-secondary' : 'btn-ghost'}`}
                style={{ padding: '5px 10px', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                onClick={() => setShowAdvancedFilter(!showAdvancedFilter)}
              >
                <SlidersHorizontal size={13} style={{ color: activeFilterCount > 0 ? 'var(--accent-cyan)' : 'inherit' }} />
                <span>高级过滤器</span>
                {activeFilterCount > 0 && (
                  <span
                    style={{
                      background: 'var(--accent-cyan)',
                      color: '#000',
                      borderRadius: '99px',
                      padding: '1px 6px',
                      fontSize: '0.7rem',
                      fontWeight: 700,
                    }}
                  >
                    {activeFilterCount}
                  </span>
                )}
                {showAdvancedFilter ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
            </div>
          </div>

          {/* 过滤器控制面板（前端控制，即时过滤与动态生效） */}
          <div className="filter-panel-card">
            {/* 第一行：常用快捷过滤标签 */}
            <div className="filter-primary-row">
              <div className="filter-chips-group">
                <span style={{ fontSize: '0.78rem', color: 'var(--text-sub)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Filter size={13} />
                  <span>星级偏好:</span>
                </span>

                <button
                  type="button"
                  className={`filter-chip ${filter.minStars === 0 ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, minStars: 0 }))}
                >
                  全部
                </button>
                <button
                  type="button"
                  className={`filter-chip ${filter.minStars === 3 ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, minStars: 3 }))}
                >
                  ⭐️ 3星+ (优质)
                </button>
                <button
                  type="button"
                  className={`filter-chip ${filter.minStars === 4 ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, minStars: 4 }))}
                >
                  ⭐️ 4星+ (极优)
                </button>
                <button
                  type="button"
                  className={`filter-chip ${filter.minStars === 5 ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, minStars: 5 }))}
                >
                  ⭐️ 5星极品
                </button>
              </div>

              {/* 关键开关 (CDN、境内、默认页) */}
              <div className="filter-chips-group">
                <button
                  type="button"
                  className={`filter-chip ${filter.requireNoCDN ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, requireNoCDN: !f.requireNoCDN }))}
                  title="仅保留源站直连目标，排除 Cloudflare/Akamai 等 CDN 域名"
                >
                  ⚡ 源站直连 (排除 CDN)
                </button>

                <button
                  type="button"
                  className={`filter-chip ${filter.requireNoCN ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, requireNoCN: !f.requireNoCN }))}
                  title="排除 .cn / 境内域名以规避境内合规风险"
                >
                  🛡️ 排除 .cn 境内域名
                </button>

                <button
                  type="button"
                  className={`filter-chip ${filter.requireNoDefaultPage ? 'active-warning' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, requireNoDefaultPage: !f.requireNoDefaultPage }))}
                  title="排除探测出 Nginx / Apache 默认欢迎页的域名"
                >
                  📄 排除默认欢迎页
                </button>
              </div>
            </div>

            {/* 域名后缀快捷过滤行 (支持多后缀逗号分隔，默认快捷 .com) */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '10px', paddingTop: '10px', borderTop: '1px solid rgba(255, 255, 255, 0.05)', flexWrap: 'wrap', gap: '8px' }}>
              <div className="filter-chips-group">
                <span style={{ fontSize: '0.78rem', color: 'var(--text-sub)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Globe size={13} style={{ color: 'var(--accent-cyan)' }} />
                  <span>域名后缀:</span>
                </span>

                <button
                  type="button"
                  className={`filter-chip ${!filter.domainSuffixes ? 'active' : ''}`}
                  onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '' }))}
                >
                  全部后缀
                </button>

                <button
                  type="button"
                  className={`filter-chip ${isSuffixSelected('.com') ? 'active' : ''}`}
                  onClick={() => toggleSuffix('.com')}
                  title="默认快捷选项：快速筛选 / 切换 .com 顶级域名"
                >
                  ⭐️ .com (默认快捷)
                </button>

                <button
                  type="button"
                  className={`filter-chip ${isSuffixSelected('.net') ? 'active' : ''}`}
                  onClick={() => toggleSuffix('.net')}
                >
                  .net
                </button>

                <button
                  type="button"
                  className={`filter-chip ${isSuffixSelected('.org') ? 'active' : ''}`}
                  onClick={() => toggleSuffix('.org')}
                >
                  .org
                </button>

                <button
                  type="button"
                  className={`filter-chip ${isSuffixSelected('.io') ? 'active' : ''}`}
                  onClick={() => toggleSuffix('.io')}
                >
                  .io
                </button>

                <button
                  type="button"
                  className={`filter-chip ${isSuffixSelected('.xyz') ? 'active' : ''}`}
                  onClick={() => toggleSuffix('.xyz')}
                >
                  .xyz
                </button>

                {filter.domainSuffixes && !['.com', '.net', '.org', '.io', '.xyz'].includes(filter.domainSuffixes.trim()) && (
                  <span className="badge badge-info" style={{ fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    已自定义: {filter.domainSuffixes}
                    <button
                      type="button"
                      onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '' }))}
                      style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 }}
                      title="清除后缀"
                    >
                      <X size={11} />
                    </button>
                  </span>
                )}
              </div>
            </div>

            {/* 第二行：高级抽屉折叠面板 */}
            {showAdvancedFilter && (
              <div className="filter-drawer">
                {/* 握手延迟限制 */}
                <div className="filter-field">
                  <label className="filter-field-label">
                    <Clock size={13} style={{ color: 'var(--accent-cyan)' }} />
                    <span>握手延迟上限</span>
                  </label>
                  <select
                    value={filter.maxHandshakeMS}
                    onChange={(e) => setFilter((f) => ({ ...f, maxHandshakeMS: Number(e.target.value) }))}
                  >
                    <option value={0}>不限延迟</option>
                    <option value={60}>≤ 60 ms (极致)</option>
                    <option value={100}>≤ 100 ms (极速)</option>
                    <option value={150}>≤ 150 ms (优良)</option>
                    <option value={220}>≤ 220 ms (标准)</option>
                    <option value={350}>≤ 350 ms (宽松)</option>
                  </select>
                </div>

                {/* 证书有效天数 */}
                <div className="filter-field">
                  <label className="filter-field-label">
                    <ShieldCheck size={13} style={{ color: 'var(--accent-emerald)' }} />
                    <span>证书剩余有效天数</span>
                  </label>
                  <select
                    value={filter.minCertDays}
                    onChange={(e) => setFilter((f) => ({ ...f, minCertDays: Number(e.target.value) }))}
                  >
                    <option value={0}>不限天数</option>
                    <option value={15}>≥ 15 天</option>
                    <option value={30}>≥ 30 天 (规避临期续费窗口)</option>
                    <option value={60}>≥ 60 天 (长期稳定)</option>
                  </select>
                </div>

                {/* 匹配范畴 */}
                <div className="filter-field">
                  <label className="filter-field-label">
                    <Globe size={13} style={{ color: 'var(--accent-fire)' }} />
                    <span>匹配范畴优先级</span>
                  </label>
                  <select
                    value={filter.matchScope}
                    onChange={(e) => setFilter((f) => ({ ...f, matchScope: e.target.value as any }))}
                  >
                    <option value="all">全量加权 (同 ASN 自动置顶)</option>
                    <option value="same_asn">仅同 ASN (极速同机房直连)</option>
                    <option value="same_country">同机房 + 同国家 (同地区)</option>
                  </select>
                </div>

                {/* HTTP 状态 */}
                <div className="filter-field">
                  <label className="filter-field-label">
                    <Server size={13} style={{ color: 'var(--text-sub)' }} />
                    <span>HTTP 响应状态</span>
                  </label>
                  <select
                    value={filter.statusFilter}
                    onChange={(e) => setFilter((f) => ({ ...f, statusFilter: e.target.value as any }))}
                  >
                    <option value="all">全部 (包含 443 协议直通)</option>
                    <option value="success_only">仅 200 OK / 正常直通 (排除 4xx/5xx)</option>
                  </select>
                </div>

                {/* 域名后缀输入与快捷多选 */}
                <div className="filter-field" style={{ gridColumn: 'span 2' }}>
                  <label className="filter-field-label">
                    <Globe size={13} style={{ color: 'var(--accent-cyan)' }} />
                    <span>指定域名后缀 (支持多个以逗号 `,` 分开，默认快捷 .com)</span>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      placeholder="例如: .com, .net, .org (支持以逗号分隔输入多个后缀)"
                      value={filter.domainSuffixes}
                      onChange={(e) => setFilter((f) => ({ ...f, domainSuffixes: e.target.value }))}
                      style={{ width: '100%', paddingRight: '28px' }}
                    />
                    {filter.domainSuffixes && (
                      <button
                        type="button"
                        onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '' }))}
                        style={{
                          position: 'absolute',
                          right: '8px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-sub)',
                          cursor: 'pointer',
                        }}
                        title="清空后缀"
                      >
                        <X size={13} />
                      </button>
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: '6px', marginTop: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-sub)' }}>快捷选填:</span>
                    <button
                      type="button"
                      className={`badge ${isSuffixSelected('.com') ? 'badge-same-asn' : 'badge-global'}`}
                      style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                      onClick={() => toggleSuffix('.com')}
                    >
                      ⭐️ .com
                    </button>
                    <button
                      type="button"
                      className={`badge ${isSuffixSelected('.net') ? 'badge-same-asn' : 'badge-global'}`}
                      style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                      onClick={() => toggleSuffix('.net')}
                    >
                      .net
                    </button>
                    <button
                      type="button"
                      className={`badge ${isSuffixSelected('.org') ? 'badge-same-asn' : 'badge-global'}`}
                      style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                      onClick={() => toggleSuffix('.org')}
                    >
                      .org
                    </button>
                    <button
                      type="button"
                      className="badge badge-global"
                      style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                      onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '.com, .net' }))}
                    >
                      组合: .com, .net
                    </button>
                    <button
                      type="button"
                      className="badge badge-global"
                      style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)' }}
                      onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '.com, .net, .org' }))}
                    >
                      组合: .com, .net, .org
                    </button>
                    {filter.domainSuffixes && (
                      <button
                        type="button"
                        className="badge badge-global"
                        style={{ cursor: 'pointer', border: '1px solid var(--border-subtle)', color: 'var(--accent-rose)' }}
                        onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '' }))}
                      >
                        清除后缀限制
                      </button>
                    )}
                  </div>
                </div>

                {/* 关键词快速筛选 */}
                <div className="filter-field" style={{ gridColumn: 'span 2' }}>
                  <label className="filter-field-label">
                    <Search size={13} style={{ color: 'var(--accent-cyan)' }} />
                    <span>域名或标题实时过滤</span>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      placeholder="输入关键字即时过滤 (如 cloud, debian, microsoft)..."
                      value={filter.keyword}
                      onChange={(e) => setFilter((f) => ({ ...f, keyword: e.target.value }))}
                      style={{ width: '100%', paddingRight: '28px' }}
                    />
                    {filter.keyword && (
                      <button
                        type="button"
                        onClick={() => setFilter((f) => ({ ...f, keyword: '' }))}
                        style={{
                          position: 'absolute',
                          right: '8px',
                          top: '50%',
                          transform: 'translateY(-50%)',
                          background: 'none',
                          border: 'none',
                          color: 'var(--text-sub)',
                          cursor: 'pointer',
                        }}
                      >
                        <X size={13} />
                      </button>
                    )}
                  </div>
                </div>

                {/* 快捷操作按钮 */}
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: '8px', paddingBottom: '2px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ padding: '6px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                    onClick={applyRecommendedFilters}
                  >
                    <Sparkles size={13} style={{ color: 'var(--accent-cyan)' }} />
                    推荐配置
                  </button>

                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ padding: '6px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                    onClick={resetFilters}
                  >
                    <RotateCcw size={13} />
                    清空条件
                  </button>
                </div>
              </div>
            )}

            {/* 结果过滤统计摘要条 */}
            <div className="filter-summary-bar">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span>
                  当前展示 <strong style={{ color: 'var(--accent-cyan)' }}>{displayedTargets.length}</strong> 个目标
                  {rawTargets.length > 0 && (
                    <span>
                      {' '}
                      (共召回 <span style={{ color: 'var(--text-main)' }}>{rawTargets.length}</span> 个候选，
                      <span style={{ color: rawTargets.length - displayedTargets.length > 0 ? 'var(--accent-amber)' : 'var(--text-sub)' }}>
                        {rawTargets.length - displayedTargets.length} 个被过滤
                      </span>
                      )
                    </span>
                  )}
                </span>
              </div>

              {/* 激活的过滤标签胶囊 */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                {filter.minStars > 0 && (
                  <span className="badge badge-warning" style={{ fontSize: '0.72rem' }}>
                    ≥{filter.minStars}星
                  </span>
                )}
                {filter.maxHandshakeMS > 0 && (
                  <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>
                    ≤{filter.maxHandshakeMS}ms
                  </span>
                )}
                {filter.requireNoCDN && (
                  <span className="badge badge-success" style={{ fontSize: '0.72rem' }}>
                    源站直连
                  </span>
                )}
                {filter.requireNoCN && (
                  <span className="badge badge-global" style={{ fontSize: '0.72rem' }}>
                    无 .cn
                  </span>
                )}
                {filter.requireNoDefaultPage && (
                  <span className="badge badge-warning" style={{ fontSize: '0.72rem' }}>
                    无默认页
                  </span>
                )}
                {filter.minCertDays > 0 && (
                  <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>
                    ≥{filter.minCertDays}天证书
                  </span>
                )}
                {filter.matchScope !== 'all' && (
                  <span className="badge badge-same-asn" style={{ fontSize: '0.72rem' }}>
                    {filter.matchScope === 'same_asn' ? '仅同ASN' : '同ASN/同国家'}
                  </span>
                )}
                {filter.keyword && (
                  <span className="badge badge-info" style={{ fontSize: '0.72rem' }}>
                    词: {filter.keyword}
                  </span>
                )}
                {filter.domainSuffixes.trim() && (
                  <span className="badge badge-info" style={{ fontSize: '0.72rem', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                    后缀: {filter.domainSuffixes}
                    <button
                      type="button"
                      onClick={() => setFilter((f) => ({ ...f, domainSuffixes: '' }))}
                      style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0 }}
                      title="清除后缀限制"
                    >
                      <X size={10} />
                    </button>
                  </span>
                )}
                {activeFilterCount > 0 && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: 'var(--text-sub)',
                      fontSize: '0.72rem',
                      cursor: 'pointer',
                      textDecoration: 'underline',
                      marginLeft: '4px',
                    }}
                  >
                    重置
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* 实时扫描进度卡片 (实时同步扫描进度) */}
          {(scanProgress.isScanning || scanProgress.message) && (
            <div className="scan-progress-card">
              <div className="scan-progress-header">
                <div className="scan-status-title">
                  {scanProgress.isScanning ? (
                    <div className="radar-ping">
                      <span className="radar-ping-ring"></span>
                      <span className="radar-ping-dot"></span>
                    </div>
                  ) : (
                    <Check size={16} style={{ color: 'var(--accent-emerald)' }} />
                  )}
                  <span>{scanProgress.message}</span>
                </div>

                {scanProgress.isScanning && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{
                      padding: '4px 12px',
                      fontSize: '0.78rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '5px',
                      color: 'var(--accent-rose)',
                      borderColor: 'rgba(244,63,94,0.4)',
                    }}
                    onClick={stopScan}
                  >
                    <Square size={12} />
                    停止扫描
                  </button>
                )}
              </div>

              {/* 实时进度条 */}
              {scanProgress.isScanning && (
                <div className="scan-progress-bar-bg">
                  <div
                    className="scan-progress-bar-fill"
                    style={{ width: `${Math.max(5, scanProgress.percent)}%` }}
                  ></div>
                </div>
              )}

              {/* 实时探测数据指标网格 */}
              <div className="scan-stats-grid">
                <div className="scan-stat-item">
                  <span className="scan-stat-label">已探测 IP / 总量</span>
                  <span className="scan-stat-value">
                    {scanProgress.scannedIPs.toLocaleString()}
                    {scanProgress.totalIPs > 0 && (
                      <span style={{ color: 'var(--text-sub)', fontSize: '0.8rem' }}>
                        {' '}/ {scanProgress.totalIPs.toLocaleString()} ({scanProgress.percent}%)
                      </span>
                    )}
                  </span>
                </div>

                <div className="scan-stat-item">
                  <span className="scan-stat-label">当前正在探测</span>
                  <span className="scan-stat-value" style={{ color: 'var(--accent-cyan)' }}>
                    {scanProgress.currentIP || scanProgress.currentCIDR || '就绪中...'}
                  </span>
                </div>

                <div className="scan-stat-item">
                  <span className="scan-stat-label">探测并发速率</span>
                  <span className="scan-stat-value" style={{ color: 'var(--accent-emerald)' }}>
                    {scanProgress.speed > 0 ? `~${scanProgress.speed} IP/s` : '计算中...'}
                  </span>
                </div>

                <div className="scan-stat-item">
                  <span className="scan-stat-label">现场即时命中 (符合过滤器 / 总数)</span>
                  <span className="scan-stat-value">
                    <span style={{ color: '#fb923c' }}>{scanProgress.matchedCount} 个</span>
                    <span style={{ color: 'var(--text-sub)', fontSize: '0.8rem' }}>
                      {' '}(共发现 {scanProgress.foundCount})
                    </span>
                  </span>
                </div>
              </div>
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

              {/* 触发实时流式扫描 */}
              {!scanProgress.isScanning ? (
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

      {/* 当数据库暂无收录资产且未在扫描时，展示醒目的【马上扫描】开关引导面板 */}
      {summary && rawTargets.length === 0 && !loading && !scanProgress.isScanning && (
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
                    点击下方按钮启动并发流水线，边扫边同步进度，有符合条件的目标即刻展示！
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

      {/* 当有目标但被过滤器全部筛除时的空提示 */}
      {rawTargets.length > 0 && displayedTargets.length === 0 && (
        <div
          className="glass-panel"
          style={{
            padding: '40px 20px',
            textAlign: 'center',
            marginTop: '24px',
            border: '1px dashed var(--border-subtle)',
          }}
        >
          <Filter size={32} style={{ color: 'var(--accent-amber)', margin: '0 auto 12px auto', opacity: 0.8 }} />
          <h4 style={{ fontSize: '1.05rem', fontWeight: 600 }}>当前没有符合过滤器的目标</h4>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-sub)', marginTop: '6px', maxWidth: '480px', margin: '6px auto 16px auto' }}>
            系统已召回 {rawTargets.length} 个候选资产，但由于当前过滤器条件较严格（如星级、延迟或关键词），它们均被隐藏。
          </p>
          <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
            <button type="button" className="btn btn-secondary" style={{ fontSize: '0.82rem' }} onClick={resetFilters}>
              清空所有过滤限制
            </button>
            <button type="button" className="btn btn-primary" style={{ fontSize: '0.82rem' }} onClick={applyRecommendedFilters}>
              恢复推荐过滤
            </button>
          </div>
        </div>
      )}

      {/* 结果区域工具栏与布局切换 */}
      {displayedTargets.length > 0 && (
        <div className="results-toolbar">
          <div className="results-toolbar-left">
            <div className="results-title-group">
              <h3 className="results-title">匹配目标结果</h3>
              <span className="badge badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
                {displayedTargets.length} 个目标
              </span>
            </div>
          </div>

          {/* 右上角布局切换按钮 */}
          <div className="results-toolbar-right">
            <div className="layout-toggle-group">
              <button
                type="button"
                className={`layout-toggle-btn ${viewMode === 'grid' ? 'active' : ''}`}
                onClick={() => handleViewModeChange('grid')}
                title="切换为卡片网格布局"
              >
                <LayoutGrid size={15} />
                <span>网格</span>
              </button>
              <button
                type="button"
                className={`layout-toggle-btn ${viewMode === 'list' ? 'active' : ''}`}
                onClick={() => handleViewModeChange('list')}
                title="切换为紧凑列表布局"
              >
                <List size={15} />
                <span>列表</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 结果视图：卡片网格模式 */}
      {viewMode === 'grid' && displayedTargets.length > 0 && (
        <div className="targets-grid">
          {displayedTargets.map((target) => {
            const isSameASN = target.match_level === 'same_asn';
            const isSameCountry = target.match_level === 'same_country';
            const isFreshlyScanned = target.domain === latestDiscoveredDomain || target.is_new_scan;

            return (
              <div
                key={target.domain}
                className={`target-card glass-panel ${isSameASN ? 'highlight-asn' : ''} ${isFreshlyScanned ? 'highlight-new' : ''}`}
              >
                <div>
                  <div className="card-top">
                    <div className="card-title-group">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
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

                        {isFreshlyScanned && (
                          <span className="badge badge-live-scan" title="实时流水线刚探测发现的目标">
                            现场即时新扫
                          </span>
                        )}

                        <span className="star-rating">
                          {'★'.repeat(target.stars)}
                        </span>
                      </div>

                      <div
                        className="card-domain"
                        style={{ marginTop: '6px', cursor: 'pointer' }}
                        onClick={() => setSelectedDetailTarget(target)}
                        title="点击查看详细信息"
                      >
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
                          <span style={{ color: target.status_code < 400 ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                            {target.status_code} OK
                          </span>
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
                  </div>
                </div>

                <div className="card-footer">
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn btn-secondary btn-open-web"
                      style={{ padding: '6px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                      onClick={(e) => openDomainUrl(target.domain, e)}
                      title="在浏览器新标签页直接打开域名网页"
                    >
                      <ExternalLink size={13} />
                      <span>打开网页</span>
                    </button>

                    <button
                      type="button"
                      className="btn btn-secondary"
                      style={{ padding: '6px 10px', fontSize: '0.8rem' }}
                      onClick={() => copyDomain(target.domain)}
                      title="复制域名"
                    >
                      {copiedDomain === target.domain ? <Check size={14} /> : <Copy size={14} />}
                      <span>{copiedDomain === target.domain ? '已复制' : '复制'}</span>
                    </button>

                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ padding: '6px 10px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '4px' }}
                      onClick={() => setSelectedDetailTarget(target)}
                      title="查看目标完整详细信息"
                    >
                      <Info size={14} />
                      <span>详情</span>
                    </button>
                  </div>

                  <button
                    type="button"
                    className="btn btn-primary"
                    style={{ padding: '6px 14px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '5px' }}
                    onClick={() => setSelectedTarget(target)}
                  >
                    <Zap size={14} />
                    <span>一键生成配置</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* 结果视图：紧凑列表模式 */}
      {viewMode === 'list' && displayedTargets.length > 0 && (
        <div className="targets-list-view">
          <table className="targets-list-table">
            <thead>
              <tr>
                <th style={{ width: '38px', textAlign: 'center' }}></th>
                <th>伪装域名 / 网站标题</th>
                <th>归属 ASN / 国家</th>
                <th>握手延时</th>
                <th>证书状态 / 有效期</th>
                <th>HTTP 状态</th>
                <th style={{ textAlign: 'right' }}>快捷操作</th>
              </tr>
            </thead>
            <tbody>
              {displayedTargets.map((target) => {
                const isSameASN = target.match_level === 'same_asn';
                const isSameCountry = target.match_level === 'same_country';
                const isFreshlyScanned = target.domain === latestDiscoveredDomain || target.is_new_scan;
                const isExpanded = expandedDomains.has(target.domain);

                return (
                  <Fragment key={target.domain}>
                    <tr
                      className={`list-row-item ${isSameASN ? 'highlight-asn' : ''} ${isExpanded ? 'is-expanded' : ''}`}
                      onClick={() => setSelectedDetailTarget(target)}
                      title="点击列表项显示详细信息"
                    >
                      {/* 展开/收起行内详情触发图标 */}
                      <td
                        style={{ textAlign: 'center', width: '38px' }}
                        onClick={(e) => toggleExpandDomain(target.domain, e)}
                      >
                        <button
                          type="button"
                          className="btn-icon"
                          style={{
                            padding: '4px',
                            background: 'transparent',
                            border: 'none',
                            color: isExpanded ? 'var(--accent-cyan)' : 'var(--text-sub)',
                            cursor: 'pointer',
                          }}
                          title={isExpanded ? '收起行内详情' : '展开行内详情'}
                        >
                          {isExpanded ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                        </button>
                      </td>

                      {/* 域名与标题 */}
                      <td>
                        <div className="list-domain-cell">
                          <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)', fontSize: '0.92rem' }}>
                            {target.domain}
                          </span>

                          {isSameASN ? (
                            <span className="badge badge-same-asn" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                              <Flame size={10} />
                              同 ASN
                            </span>
                          ) : isSameCountry ? (
                            <span className="badge badge-same-country" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                              <Globe size={10} />
                              同国家
                            </span>
                          ) : (
                            <span className="badge badge-global" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                              全球
                            </span>
                          )}

                          {isFreshlyScanned && (
                            <span className="badge badge-live-scan" style={{ fontSize: '0.68rem', padding: '1px 6px' }}>
                              新扫
                            </span>
                          )}

                          <span className="star-rating" style={{ fontSize: '0.78rem' }}>
                            {'★'.repeat(target.stars)}
                          </span>
                        </div>

                        {target.page_title && (
                          <div className="list-domain-title" title={target.page_title}>
                            {target.page_title}
                          </div>
                        )}
                      </td>

                      {/* ASN 与国家 */}
                      <td>
                        <span style={{ color: isSameASN ? 'var(--accent-fire)' : 'var(--text-main)', fontWeight: isSameASN ? 600 : 400 }}>
                          {target.asn || '未知'} ({target.country || 'N/A'})
                        </span>
                      </td>

                      {/* 握手延迟 */}
                      <td>
                        <span
                          className="font-mono"
                          style={{
                            fontWeight: 600,
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
                      </td>

                      {/* 证书天数与到期 */}
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <span
                            style={{
                              fontWeight: 600,
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
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-sub)' }}>
                            {formatCertExpireDate(target.cert_expire_at, target.cert_days)}
                          </span>
                        </div>
                      </td>

                      {/* HTTP 状态 */}
                      <td>
                        {target.status_code > 0 ? (
                          <span
                            className="badge"
                            style={{
                              background: target.status_code < 400 ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                              color: target.status_code < 400 ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                              border: `1px solid ${target.status_code < 400 ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                              fontSize: '0.72rem',
                            }}
                          >
                            {target.status_code} OK
                          </span>
                        ) : (
                          <span className="badge badge-global" style={{ fontSize: '0.72rem' }}>443 直通</span>
                        )}
                      </td>

                      {/* 列表行操作按钮组 */}
                      <td>
                        <div className="list-actions-cell">
                          {/* 列表上的打开网页按钮：点击直接打开域名网页（新标签） */}
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm btn-open-web"
                            onClick={(e) => openDomainUrl(target.domain, e)}
                            title="在浏览器新标签页直接打开域名网页"
                          >
                            <ExternalLink size={13} />
                            <span>打开网页</span>
                          </button>

                          {/* 一键配置按钮 */}
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedTarget(target);
                            }}
                            title="一键生成 REALITY 配置"
                          >
                            <Zap size={13} />
                            <span>配置</span>
                          </button>

                          {/* 复制域名按钮 */}
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              copyDomain(target.domain);
                            }}
                            title="复制域名"
                          >
                            {copiedDomain === target.domain ? <Check size={13} style={{ color: 'var(--accent-emerald)' }} /> : <Copy size={13} />}
                          </button>

                          {/* 详情弹窗按钮 */}
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedDetailTarget(target);
                            }}
                            title="查看详细信息"
                          >
                            <Info size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* 行内可折叠展开的详细信息 */}
                    {isExpanded && (
                      <tr className="list-expanded-row">
                        <td colSpan={7}>
                          <div className="list-expanded-content">
                            <div className="inline-detail-grid">
                              {/* 1. 域名 */}
                              <div className="inline-detail-item">
                                <div className="inline-detail-label">
                                  <Globe size={12} style={{ color: 'var(--accent-cyan)' }} />
                                  <span>域名 (Domain)</span>
                                </div>
                                <div className="inline-detail-value font-mono">
                                  {target.domain}
                                </div>
                              </div>

                              {/* 2. 标题 */}
                              <div className="inline-detail-item" style={{ gridColumn: 'span 2' }}>
                                <div className="inline-detail-label">
                                  <FileText size={12} style={{ color: 'var(--accent-amber)' }} />
                                  <span>网站标题 (Title)</span>
                                </div>
                                <div className="inline-detail-value" style={{ fontWeight: 500, fontSize: '0.86rem' }}>
                                  {target.page_title || '（未获取到标题 / 443 协议直通）'}
                                </div>
                              </div>

                              {/* 3. 证书剩余时间 */}
                              <div className="inline-detail-item">
                                <div className="inline-detail-label">
                                  <Clock size={12} style={{ color: 'var(--accent-emerald)' }} />
                                  <span>证书剩余时间</span>
                                </div>
                                <div
                                  className="inline-detail-value font-mono"
                                  style={{
                                    color:
                                      target.cert_days <= 0
                                        ? 'var(--accent-rose)'
                                        : target.cert_days < 30
                                        ? 'var(--accent-amber)'
                                        : 'var(--accent-emerald)',
                                  }}
                                >
                                  {target.cert_days <= 0 ? '已过期' : `${target.cert_days} 天`}
                                </div>
                              </div>

                              {/* 4. 到期时间 */}
                              <div className="inline-detail-item">
                                <div className="inline-detail-label">
                                  <Calendar size={12} style={{ color: 'var(--accent-fire)' }} />
                                  <span>到期时间 (Expiration)</span>
                                </div>
                                <div className="inline-detail-value font-mono" style={{ fontSize: '0.84rem' }}>
                                  {formatCertExpireDate(target.cert_expire_at, target.cert_days)}
                                </div>
                              </div>

                              {/* 进阶指标: 握手延迟与 IP */}
                              <div className="inline-detail-item">
                                <div className="inline-detail-label">
                                  <Clock size={12} />
                                  <span>TLS 握手延时 / 解析 IP</span>
                                </div>
                                <div className="inline-detail-value font-mono" style={{ fontSize: '0.84rem' }}>
                                  {target.handshake_ms} ms · {target.ip || '直连'}
                                </div>
                              </div>

                              {/* 详情弹窗跳转 */}
                              <div className="inline-detail-item" style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'flex-end' }}>
                                <button
                                  type="button"
                                  className="btn btn-secondary btn-sm"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedDetailTarget(target);
                                  }}
                                  style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.78rem' }}
                                >
                                  <Info size={13} />
                                  <span>打开完整详情弹窗</span>
                                </button>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {!summary && rawTargets.length === 0 && !loading && (
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

      {/* 目标资产详细信息弹窗 */}
      <TargetDetailModal
        target={selectedDetailTarget}
        onClose={() => setSelectedDetailTarget(null)}
        onOpenConfig={(target) => setSelectedTarget(target)}
      />

      {/* 导出配置弹窗 */}
      <ConfigModal
        target={selectedTarget}
        serverIP={ip.trim()}
        onClose={() => setSelectedTarget(null)}
      />
    </div>
  );
};

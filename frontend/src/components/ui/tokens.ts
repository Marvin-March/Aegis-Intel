// 统一语义色阶与风险元数据（Vulners + Feedly + Grafana 规范）

export interface SeverityMeta {
  key: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  label: string;
  zhLabel: string;
  color: string;
  badgeClass: string;
  barClass: string;
  dotClass: string;
}

export const SEVERITY_META: Record<string, SeverityMeta> = {
  CRITICAL: {
    key: 'CRITICAL',
    label: 'CRITICAL',
    zhLabel: '严重',
    color: '#ef4444',
    badgeClass: 'bg-red-500/15 text-red-400 border-red-500/35',
    barClass: 'bg-red-500',
    dotClass: 'bg-red-500',
  },
  HIGH: {
    key: 'HIGH',
    label: 'HIGH',
    zhLabel: '高危',
    color: '#f97316',
    badgeClass: 'bg-orange-500/15 text-orange-400 border-orange-500/35',
    barClass: 'bg-orange-500',
    dotClass: 'bg-orange-500',
  },
  MEDIUM: {
    key: 'MEDIUM',
    label: 'MEDIUM',
    zhLabel: '中危',
    color: '#eab308',
    badgeClass: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/35',
    barClass: 'bg-yellow-500',
    dotClass: 'bg-yellow-500',
  },
  LOW: {
    key: 'LOW',
    label: 'LOW',
    zhLabel: '低危',
    color: '#3b82f6',
    badgeClass: 'bg-blue-500/15 text-blue-400 border-blue-500/35',
    barClass: 'bg-blue-500',
    dotClass: 'bg-blue-500',
  },
};

export function getSeverityMeta(severity?: string | null): SeverityMeta {
  const key = (severity ?? '').toUpperCase();
  return (
    SEVERITY_META[key] ?? {
      key: 'UNKNOWN',
      label: key || 'N/A',
      zhLabel: '未知',
      color: '#64748b',
      badgeClass: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
      barClass: 'bg-slate-500',
      dotClass: 'bg-slate-500',
    }
  );
}

export interface DomainMeta {
  key: string;
  label: string;
  zhLabel: string;
  color: string;
  badgeClass: string;
}

export const DOMAIN_META: Record<string, DomainMeta> = {
  cve: {
    key: 'cve',
    label: 'CVE',
    zhLabel: '漏洞库',
    color: '#f43f5e',
    badgeClass: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  },
  article: {
    key: 'article',
    label: 'ARTICLE',
    zhLabel: '资讯文章',
    color: '#38bdf8',
    badgeClass: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  },
  paper: {
    key: 'paper',
    label: 'PAPER',
    zhLabel: '学术论文',
    color: '#a78bfa',
    badgeClass: 'bg-violet-500/15 text-violet-400 border-violet-500/30',
  },
  daily: {
    key: 'daily',
    label: 'DAILY',
    zhLabel: '每日简报',
    color: '#10b981',
    badgeClass: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  },
};

export function getDomainMeta(domain?: string): DomainMeta {
  const key = (domain ?? '').toLowerCase();
  return (
    DOMAIN_META[key] ?? {
      key: key || 'other',
      label: (domain || 'INTEL').toUpperCase(),
      zhLabel: '情报',
      color: '#64748b',
      badgeClass: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
    }
  );
}

/** 拆解受影响组件字符串为独立标签，便于快速扫描 */
export function parseAffectedComponents(raw?: string): string[] {
  if (!raw) return [];
  return raw
    .split(/[,;/|、]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

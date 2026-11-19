import { ExternalLink, AlertTriangle } from 'lucide-react';
import type { VulnCard as CVECardType } from '../types/contract';

interface Props {
  card: CVECardType;
  compact?: boolean;
  animate?: boolean;
  /** 入场延迟 ms（animate 时生效，错峰滑入） */
  delay?: number;
}

const severityStyle: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: '#f87171', label: 'CRITICAL' },
  HIGH: { color: '#fb923c', label: 'HIGH' },
  MEDIUM: { color: '#fbbf24', label: 'MEDIUM' },
  LOW: { color: '#94a3b8', label: 'LOW' },
};

export default function CVECard({ card, compact = false, animate = false, delay = 0 }: Props) {
  if (!card || !card.cve_id) return null;
  const sev = severityStyle[card.severity] ?? severityStyle.LOW;

  return (
    <div
      style={animate && delay > 0 ? { animationDelay: `${delay}ms` } : undefined}
      className={`relative bg-soc-panel border border-soc-border ${compact ? 'p-3' : 'p-4'} transition-colors hover:border-soc-primary/35 ${
        animate ? 'animate-fade-slide-in' : ''
      }`}
    >
      {/* 严重度左指示条 */}
      <div className="absolute left-0 top-0 bottom-0 w-[2px]" style={{ background: sev.color, opacity: 0.8 }} />

      {/* 头部：CVE 编号 + 徽章 */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <a
          href={card.url}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-sm text-soc-primary hover:text-[#e0bd7d] transition-colors flex items-center gap-1.5"
        >
          {card.cve_id}
          <ExternalLink size={11} />
        </a>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {card.kev === 1 && (
            <span className="px-1.5 py-0.5 border border-soc-danger/60 text-soc-danger text-[10px] font-mono tracking-wider flex items-center gap-1">
              <AlertTriangle size={10} />
              KEV 在野
            </span>
          )}
          <span
            className="px-1.5 py-0.5 border text-[10px] font-mono tracking-wider"
            style={{ borderColor: `${sev.color}80`, color: sev.color }}
          >
            {sev.label}
          </span>
        </div>
      </div>

      {/* 指标行（缺失字段该行隐藏） */}
      <div className="flex items-center gap-4 mb-3 pb-3 border-b border-soc-border">
        {typeof card.cvss === 'number' && (
          <div className="flex items-baseline gap-1.5">
            <span className="text-[10px] font-mono tracking-wider text-soc-text-muted">CVSS</span>
            <span className="text-lg font-mono text-soc-text-primary leading-none">{card.cvss}</span>
          </div>
        )}
        {typeof card.epss === 'number' && (
          <div className="flex items-baseline gap-1.5">
            <span className="text-[10px] font-mono tracking-wider text-soc-text-muted">EPSS</span>
            <span className="text-sm font-mono text-soc-text-secondary leading-none">
              {(card.epss * 100).toFixed(1)}%
            </span>
          </div>
        )}
        {card.affected_component && (
          <div className="flex items-baseline gap-1.5 min-w-0">
            <span className="text-[10px] font-mono tracking-wider text-soc-text-muted flex-shrink-0">COMP</span>
            <span className="text-sm font-mono text-soc-text-secondary truncate">{card.affected_component}</span>
          </div>
        )}
      </div>

      <div className="space-y-2.5">
        {card.attack_type && (
          <div className="flex gap-2 text-sm">
            <span className="text-soc-text-muted flex-shrink-0 text-xs pt-0.5">攻击类型</span>
            <span className="text-soc-text-primary text-xs pt-0.5">{card.attack_type}</span>
          </div>
        )}

        {!compact && card.summary_zh && (
          <div>
            <p className="soc-eyebrow mb-1.5">摘要</p>
            <p className="text-sm text-soc-text-secondary leading-relaxed">{card.summary_zh}</p>
          </div>
        )}
        {!compact && card.remediation_zh && (
          <div>
            <p className="soc-eyebrow mb-1.5">修复建议</p>
            <p className="text-sm text-soc-text-secondary leading-relaxed">{card.remediation_zh}</p>
          </div>
        )}
      </div>
    </div>
  );
}

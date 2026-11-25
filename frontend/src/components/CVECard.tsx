import { ExternalLink, Wrench, Tag } from 'lucide-react';
import type { VulnCard as CVECardType } from '../types/contract';
import { getSeverityMeta, parseAffectedComponents } from './ui/tokens';
import { SeverityBadge, KevBadge, ComponentBadge } from './ui/Badge';

interface Props {
  card: CVECardType;
  index?: number;
  compact?: boolean;
  animate?: boolean;
  delay?: number;
}

/**
 * 精密 SVG 环形 CVSS 仪表盘（带刻度环与柔和语义微光）
 */
function CvssRingGauge({ score, color }: { score: number; color: string }) {
  const clamped = Math.min(Math.max(score, 0), 10);
  const r = 24;
  const c = 2 * Math.PI * r;
  const dash = (clamped / 10) * c;

  return (
    <div className="relative w-16 h-16 flex-shrink-0 flex items-center justify-center">
      <svg viewBox="0 0 64 64" className="w-full h-full -rotate-90">
        {/* 外圈精密刻度 */}
        <circle
          cx="32"
          cy="32"
          r="29"
          fill="none"
          stroke="rgba(255,255,255,0.08)"
          strokeWidth="1"
          strokeDasharray="1.5 4.5"
        />
        {/* 底轨 */}
        <circle
          cx="32"
          cy="32"
          r={r}
          fill="none"
          stroke="rgba(255,255,255,0.07)"
          strokeWidth="4.5"
        />
        {/* 进度发光弧 */}
        <circle
          cx="32"
          cy="32"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="4.5"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${c}`}
          className="anim-ring"
          style={{ filter: `drop-shadow(0 0 5px ${color}88)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span
          className="text-sm font-mono font-semibold tabular-nums leading-none"
          style={{ color }}
        >
          {clamped.toFixed(1)}
        </span>
        <span className="text-[8px] font-mono tracking-widest text-slate-500 mt-0.5">CVSS</span>
      </div>
    </div>
  );
}

export default function CVECard({
  card,
  index,
  compact = false,
  animate = false,
  delay = 0,
}: Props) {
  if (!card || !card.cve_id) return null;

  const sev = getSeverityMeta(card.severity);
  const components = parseAffectedComponents(card.affected_component);
  const hasCvss = typeof card.cvss === 'number' && isFinite(card.cvss);

  return (
    <article
      style={animate && delay > 0 ? { animationDelay: `${delay}ms` } : undefined}
      className={`relative overflow-hidden aegis-surface laser-rim spotlight-card hover:border-white/[0.16] transition-colors ${
        animate ? 'anim-rise' : ''
      }`}
    >
      {/* 极克制的左上角风险微光晕 */}
      <div
        className="absolute -top-12 -left-12 w-36 h-36 rounded-full blur-2xl pointer-events-none opacity-15"
        style={{ backgroundColor: sev.color }}
      />

      <div className={`relative ${compact ? 'p-3.5' : 'p-5'}`}>
        <div className="flex items-start gap-4">
          {/* 左侧精密 SVG 环形 CVSS 仪表盘 */}
          {hasCvss && <CvssRingGauge score={card.cvss} color={sev.color} />}

          <div className="flex-1 min-w-0">
            {/* Header: CVE ID + Risk Badges */}
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-2 min-w-0 flex-wrap">
                {index !== undefined && (
                  <span className="px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-200 text-[10px] font-mono">
                    卡{index + 1}
                  </span>
                )}
                <a
                  href={card.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-base font-semibold text-white hover:text-sky-300 transition-colors inline-flex items-center gap-1.5 tracking-tight"
                >
                  {card.cve_id}
                  <ExternalLink size={12} className="opacity-70" />
                </a>
                {card.attack_type && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-white/[0.04] border border-white/[0.08] text-[10px] text-slate-300">
                    <Tag size={9} className="text-slate-400" />
                    {card.attack_type}
                  </span>
                )}
              </div>

              <div className="flex items-center gap-1.5 flex-shrink-0">
                {card.kev === 1 && <KevBadge />}
                <SeverityBadge severity={card.severity} />
              </div>
            </div>

            {/* Secondary Telemetry: EPSS + Affected Components */}
            <div className="mt-2.5 flex items-center gap-4 flex-wrap">
              {typeof card.epss === 'number' && isFinite(card.epss) && (
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono uppercase text-slate-500">EPSS</span>
                  <span className="text-xs font-mono text-slate-200 tabular-nums">
                    {(card.epss * 100).toFixed(1)}%
                  </span>
                </div>
              )}

              {components.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap min-w-0">
                  <span className="text-[10px] font-mono uppercase text-slate-500">受影响组件</span>
                  {components.map((comp) => (
                    <ComponentBadge key={comp} name={comp} />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Summary & Remediation */}
        {!compact && (card.summary_zh || card.remediation_zh) && (
          <div className="mt-4 pt-3.5 border-t border-white/[0.06] space-y-3">
            {card.summary_zh && (
              <p className="text-[13px] text-slate-300 leading-relaxed">{card.summary_zh}</p>
            )}

            {card.remediation_zh && (
              <div className="rounded-xl bg-emerald-500/[0.06] border border-emerald-400/20 px-4 py-3">
                <p className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-wider text-emerald-300 mb-1">
                  <Wrench size={10} />
                  修复建议
                </p>
                <p className="text-[13px] text-slate-100 leading-relaxed">
                  {card.remediation_zh}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </article>
  );
}

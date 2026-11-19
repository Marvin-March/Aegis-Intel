import { useState, useEffect } from 'react';
import { ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';
import type { NormalizedHit } from '../types/contract';

interface Props {
  hit: NormalizedHit;
  index: number;
  /** true = 错峰滑入 + 分数条从 0 动画；历史消息直出 */
  animate?: boolean;
  /** 自身入场延迟 ms（animate 时生效） */
  delay?: number;
}

const domainLabels: Record<string, string> = {
  cve: 'CVE',
  article: 'ARTICLE',
  paper: 'PAPER',
  daily: 'DAILY',
};

const domainAccent: Record<string, string> = {
  cve: '#f87171',
  article: '#38bdf8',
  paper: '#a78bfa',
  daily: '#34d399',
};

export default function HitCard({ hit, index, animate = false, delay = 0 }: Props) {
  const [expanded, setExpanded] = useState(false);
  const cveIds = Array.isArray(hit.cve_ids) ? hit.cve_ids : [];
  const text = hit.text ?? '';
  const hasScore = typeof hit.score === 'number' && isFinite(hit.score);
  const scorePct = hasScore ? Math.min((hit.score as number) * 100, 100) : 0;
  const accent = domainAccent[hit.domain] ?? '#646872';

  // 分数条从 0 动画到目标值
  const [barPct, setBarPct] = useState(animate ? 0 : scorePct);
  useEffect(() => {
    if (!animate) return;
    const timer = setTimeout(() => setBarPct(scorePct), 120);
    return () => clearTimeout(timer);
  }, [scorePct, animate]);

  return (
    <div
      id={`hit-${index}`}
      style={animate && delay > 0 ? { animationDelay: `${delay}ms` } : undefined}
      className={`relative soc-glass pl-5 p-4 transition-colors hover:border-soc-primary/35 ${
        animate ? 'animate-fade-slide-in' : ''
      }`}
    >
      {/* 域色左指示条（入场时自下而上展开） */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[2px]"
        style={{
          background: accent,
          opacity: 0.85,
          transformOrigin: 'top',
          animation: animate ? 'line-grow 0.5s ease-out both' : undefined,
        }}
      />

      {/* 头部行：域标 + 分数 */}
      <div className="flex items-center gap-3 mb-2">
        <span
          className="inline-flex items-center px-1.5 py-0.5 border text-[10px] font-mono tracking-[0.16em] flex-shrink-0"
          style={{ borderColor: `${accent}66`, color: accent }}
        >
          {domainLabels[hit.domain] ?? hit.domain ?? 'N/A'}
        </span>
        {hit.title && (
          <h4 className="flex-1 text-sm text-soc-text-primary truncate">{hit.title}</h4>
        )}
        {hasScore && (
          <span className="text-xs font-mono text-soc-text-secondary flex-shrink-0">
            {(hit.score as number).toFixed(3)}
          </span>
        )}
      </div>

      {/* 分数条 */}
      {hasScore && (
        <div className="relative h-[3px] bg-soc-border overflow-hidden mb-3">
          <div
            className="h-full transition-all duration-1000 ease-out relative overflow-hidden"
            style={{ width: `${barPct}%`, background: accent }}
          >
            <span className="absolute inset-0 soc-bar-shine" />
          </div>
        </div>
      )}

      {/* 元信息 */}
      <div className="flex items-center gap-3 text-[11px] text-soc-text-muted mb-2.5 flex-wrap font-mono">
        {hit.source && <span>{hit.source}</span>}
        {hit.publish_time && <span>{hit.publish_time}</span>}
        {cveIds.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap">
            {cveIds.map((cve) => (
              <span key={cve} className="px-1.5 py-0.5 border border-soc-border text-soc-text-secondary">
                {cve}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* 正文 */}
      <div className="relative">
        <p className={`text-sm text-soc-text-secondary leading-relaxed ${!expanded && 'line-clamp-3'}`}>
          {text}
        </p>
        {text.length > 200 && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="mt-2 flex items-center gap-1 text-xs text-soc-primary hover:text-[#e0bd7d] transition-colors"
          >
            {expanded ? (
              <>
                <ChevronUp size={13} />
                收起
              </>
            ) : (
              <>
                <ChevronDown size={13} />
                展开全文
              </>
            )}
          </button>
        )}
      </div>

      {/* 原文链接 */}
      {hit.url && (
        <a
          href={hit.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 mt-3 text-xs text-soc-text-muted hover:text-soc-primary transition-colors font-mono"
        >
          <ExternalLink size={11} />
          SOURCE
        </a>
      )}
    </div>
  );
}

import { useState } from 'react';
import { ExternalLink, ChevronDown, ChevronUp, Sparkles } from 'lucide-react';
import type { NormalizedHit } from '../types/contract';
import { getDomainMeta } from './ui/tokens';
import { DomainBadge } from './ui/Badge';

interface Props {
  hit: NormalizedHit;
  index: number;
  animate?: boolean;
  delay?: number;
}

export default function HitCard({ hit, index, animate = false, delay = 0 }: Props) {
  const [expanded, setExpanded] = useState(false);
  const cveIds = Array.isArray(hit.cve_ids) ? hit.cve_ids : [];
  const text = hit.text ?? '';
  const hasScore = typeof hit.score === 'number' && isFinite(hit.score);
  const scorePct = hasScore ? Math.min(Math.max((hit.score as number) * 100, 0), 100) : 0;
  const domainMeta = getDomainMeta(hit.domain);

  return (
    <article
      id={`hit-${index}`}
      style={animate && delay > 0 ? { animationDelay: `${delay}ms` } : undefined}
      className={`relative rounded-md bg-soc-panel border border-soc-border hover:border-soc-border-strong transition-colors px-3.5 py-2.5 ${
        animate ? 'animate-fade-in' : ''
      }`}
    >
      {/* Header: Citation Index + Domain + Title + Score */}
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1 rounded bg-soc-primary/15 border border-soc-primary/35 text-[10px] font-mono text-soc-primary tabular-nums flex-shrink-0">
          {index + 1}
        </span>
        <DomainBadge domain={hit.domain} />
        <h4 className="flex-1 text-xs font-medium text-soc-text-primary truncate" title={hit.title}>
          {hit.title || '未命名情报片段'}
        </h4>
        {hasScore && (
          <div className="flex items-center gap-2 flex-shrink-0">
            <div className="hidden sm:block w-14 h-1.5 rounded-full bg-soc-bg overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{ width: `${scorePct}%`, backgroundColor: domainMeta.color }}
              />
            </div>
            <span className="text-[11px] font-mono text-soc-text-secondary tabular-nums">
              {(hit.score as number).toFixed(3)}
            </span>
          </div>
        )}
      </div>

      {/* Metadata Row: Source + Time + AI Tag + CVE Chips + External Link */}
      <div className="flex items-center gap-2 mt-1.5 flex-wrap text-[11px] font-mono text-soc-text-muted">
        {hit.source && <span className="text-soc-text-secondary">{hit.source}</span>}
        {hit.source && hit.publish_time && <span>·</span>}
        {hit.publish_time && <span className="tabular-nums">{hit.publish_time}</span>}
        {hit.ai_related === 1 && (
          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-[10px] text-cyan-300">
            <Sparkles size={9} />
            AI
          </span>
        )}
        {cveIds.map((cve) => (
          <span
            key={cve}
            className="px-1.5 py-0.5 rounded bg-soc-bg border border-soc-border text-[10px] text-rose-300"
          >
            {cve}
          </span>
        ))}
        {hit.url && (
          <a
            href={hit.url}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-[11px] text-soc-text-muted hover:text-soc-primary transition-colors"
          >
            原文
            <ExternalLink size={10} />
          </a>
        )}
      </div>

      {/* Content Excerpt */}
      {text && (
        <div className="mt-2">
          <p
            className={`text-xs text-soc-text-secondary leading-relaxed ${
              !expanded ? 'line-clamp-2' : ''
            }`}
          >
            {text}
          </p>
          {text.length > 160 && (
            <button
              onClick={() => setExpanded(!expanded)}
              className="mt-1 inline-flex items-center gap-1 text-[11px] text-soc-primary hover:underline"
            >
              {expanded ? (
                <>
                  <ChevronUp size={12} />
                  收起全文
                </>
              ) : (
                <>
                  <ChevronDown size={12} />
                  展开全文
                </>
              )}
            </button>
          )}
        </div>
      )}
    </article>
  );
}

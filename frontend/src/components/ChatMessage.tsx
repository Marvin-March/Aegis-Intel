import { useState, useEffect, useRef, useCallback, memo } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  ShieldAlert,
  Link2,
  ExternalLink,
  Download,
} from 'lucide-react';
import type { NormalizedQA, NormalizedHit, RelatedArticle } from '../types/contract';
import { getRelated } from '../api/client';
import { downloadQABriefMarkdown } from '../utils/exportBrief';
import { toast } from './Toast';
import HitCard from './HitCard';
import CVECard from './CVECard';
import AnswerText, { renderTextWithUrl } from './AnswerText';
import type { EvidenceSelection } from './EvidenceDrawer';

function RelatedPanel({ cveIds }: { cveIds: string[] }) {
  const [open, setOpen] = useState(false);
  const [articles, setArticles] = useState<RelatedArticle[] | null>(null);
  const [loading, setLoading] = useState(false);

  const uniqueIds = Array.from(new Set(cveIds));
  if (uniqueIds.length === 0) return null;

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && articles === null) {
      setLoading(true);
      try {
        const r = await getRelated(uniqueIds);
        setArticles(r.articles ?? []);
      } catch {
        setArticles([]);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="rounded-xl bg-white/[0.025] border border-white/[0.07]">
      <button
        onClick={toggle}
        className="flex items-center justify-between gap-2 w-full px-3.5 py-2.5 text-left text-xs text-slate-300 hover:text-white transition-colors"
      >
        <span className="flex items-center gap-2">
          <Link2 size={13} className="text-indigo-400" />
          <span className="font-medium">关联分析文章反查</span>
          <span className="px-1.5 py-0.5 rounded bg-white/[0.05] text-[10px] font-mono text-slate-400 tabular-nums">
            {uniqueIds.length} CVE
          </span>
        </span>
        {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
      </button>
      {open && (
        <div className="px-3.5 pb-3 pt-2 space-y-1.5 border-t border-white/[0.06]">
          {loading ? (
            <p className="text-xs text-slate-400 flex items-center gap-2 py-1">
              <span className="soc-dots">
                <span />
                <span />
                <span />
              </span>
              缝合表反查中...
            </p>
          ) : (articles ?? []).length === 0 ? (
            <p className="text-xs text-slate-500 py-1">未检索到关联分析文章</p>
          ) : (
            (articles ?? []).map((a, i) => (
              <a
                key={`${a.url}-${i}`}
                href={a.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/[0.04] text-xs text-slate-300 hover:text-white transition-colors"
              >
                <span className="font-mono text-[10px] text-indigo-300 bg-indigo-500/15 px-1.5 py-0.5 rounded flex-shrink-0">
                  {a.cve_id}
                </span>
                <span className="truncate flex-1">{a.title}</span>
                <span className="text-slate-500 flex-shrink-0 font-mono text-[10px] tabular-nums">
                  {a.source} · {a.publish_time}
                </span>
                <ExternalLink size={11} className="text-slate-500 flex-shrink-0" />
              </a>
            ))
          )}
        </div>
      )}
    </div>
  );
}

interface Props {
  role: 'user' | 'assistant';
  content: string;
  userQuery?: string;
  response?: NormalizedQA;
  animated?: boolean;
  demo?: boolean;
  onInspect?: (item: EvidenceSelection) => void;
  onAnswerComplete?: () => void;
}

function ChatMessage({
  role,
  content,
  userQuery = '',
  response,
  animated = false,
  demo = false,
  onInspect,
  onAnswerComplete,
}: Props) {
  const [showAnswer, setShowAnswer] = useState(!animated);
  const [copied, setCopied] = useState(false);
  const [hitsOpen, setHitsOpen] = useState(true);
  const [domainFilter, setDomainFilter] = useState<string>('all');
  const completeRef = useRef(onAnswerComplete);
  completeRef.current = onAnswerComplete;
  const handleComplete = useCallback(() => completeRef.current?.(), []);

  const copyAnswer = useCallback(async () => {
    const text = response?.answer ?? '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
      } catch {
        /* ignore */
      }
      document.body.removeChild(ta);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }, [response]);

  const handleExportBrief = useCallback(() => {
    if (!response) return;
    const filename = downloadQABriefMarkdown(userQuery || '安全情报研判', response);
    toast.success(`已导出研判简报：${filename}`);
  }, [response, userQuery]);

  useEffect(() => {
    if (!response || role !== 'assistant' || !animated) return;
    if (response.refused) {
      const timer = setTimeout(() => setShowAnswer(true), demo ? 2600 : 0);
      return () => clearTimeout(timer);
    }
    const timer = setTimeout(() => setShowAnswer(true), demo ? 3000 : 600);
    return () => clearTimeout(timer);
  }, [response, role, animated, demo]);

  useEffect(() => {
    if (!showAnswer || !response?.refused) return;
    const timer = setTimeout(() => handleComplete(), 400);
    return () => clearTimeout(timer);
  }, [showAnswer, response, handleComplete]);

  if (role === 'user') {
    return (
      <div className="pt-1 anim-rise">
        <h2 className="text-[20px] sm:text-[22px] font-semibold tracking-tight text-white leading-snug whitespace-pre-wrap">
          {content}
        </h2>
      </div>
    );
  }

  if (!response) return null;

  const hits: NormalizedHit[] = response.hits ?? [];
  const cards = response.cards ?? [];
  const refused = response.refused;
  const answerReady = response.answer !== undefined;
  const answerText = response.answer ?? '';
  const flagged = response.fabrications ?? 0;

  const handleCiteClick = (type: 'hit' | 'card', idx: number) => {
    if (!onInspect) return;
    if (type === 'card' && cards[idx]) {
      onInspect({ kind: 'card', index: idx, card: cards[idx] });
    } else if (type === 'hit' && hits[idx]) {
      onInspect({ kind: 'hit', index: idx, hit: hits[idx] });
    }
  };

  const domainCounts = hits.reduce<Record<string, number>>((acc, h) => {
    const key = (h?.domain || 'other').toLowerCase();
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  const domainTabs = Object.keys(domainCounts);
  const visibleHits = hits
    .map((hit, idx) => ({ hit, idx }))
    .filter(({ hit }) => domainFilter === 'all' || (hit?.domain || 'other').toLowerCase() === domainFilter);

  return (
    <div className="space-y-6 pb-8 border-b border-white/[0.06] last:border-b-0 anim-rise">
      {/* 1. Minimal Single-Line Execution Trace */}
      <div className="flex items-center gap-3 flex-wrap text-[11px] font-mono text-slate-400">
        <span className="inline-flex items-center gap-1.5 text-sky-300">
          <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
          {response.route?.reason || response.route?.branch || '检索完成'}
        </span>
        <span className="text-white/15">/</span>
        <span>召回 {hits.length} 条</span>
        <span className="text-white/15">/</span>
        <span>缝合 {cards.length} 漏洞卡</span>
        <span className="text-white/15">/</span>
        <span className={flagged === 0 ? 'text-emerald-400' : 'text-amber-300'}>
          {flagged === 0 ? '0 幻觉校验通过' : `拦截 ${flagged} 处幻觉`}
        </span>
        {response.elapsed_s !== undefined && (
          <span className="ml-auto text-slate-500 tabular-nums">
            {response.elapsed_s.toFixed(1)}s
          </span>
        )}
      </div>

      {/* 2. Perplexity-Style 4-Column Source Cards Strip (Click opens Evidence Drawer) */}
      {(cards.length > 0 || hits.length > 0) && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          {cards.slice(0, 2).map((c, i) => (
            <button
              key={`src-card-${c.cve_id}-${i}`}
              type="button"
              onClick={() => handleCiteClick('card', i)}
              className="aegis-surface spotlight-card p-3 text-left hover:border-white/[0.18] transition-colors"
            >
              <div className="flex items-center justify-between gap-1 text-[10px] font-mono">
                <span className="text-indigo-300">[卡{i + 1}] CVE</span>
                {typeof c.cvss === 'number' && (
                  <span className="text-rose-400 font-semibold tabular-nums">
                    {c.cvss.toFixed(1)}
                  </span>
                )}
              </div>
              <p className="text-xs font-mono font-semibold text-white truncate mt-1.5">
                {c.cve_id}
              </p>
              <p className="text-[11px] text-slate-400 truncate mt-0.5">
                {c.affected_component || c.attack_type || '点击查看详情'}
              </p>
            </button>
          ))}
          {hits.slice(0, Math.max(4 - Math.min(cards.length, 2), 1)).map((h, i) => (
            <button
              key={`src-hit-${i}`}
              type="button"
              onClick={() => handleCiteClick('hit', i)}
              className="aegis-surface spotlight-card p-3 text-left hover:border-white/[0.18] transition-colors"
            >
              <div className="flex items-center justify-between gap-1 text-[10px] font-mono">
                <span className="text-sky-300">
                  [{i + 1}] {(h.domain || 'INTEL').toUpperCase()}
                </span>
                {typeof h.score === 'number' && (
                  <span className="text-slate-500 tabular-nums">{h.score.toFixed(2)}</span>
                )}
              </div>
              <p className="text-xs text-slate-200 line-clamp-1 mt-1.5">
                {h.title || '情报片段'}
              </p>
              <p className="text-[11px] text-slate-500 truncate mt-0.5">
                {h.source || h.publish_time || '点击查看原文'}
              </p>
            </button>
          ))}
        </div>
      )}

      {/* 3. Open Borderless AI Answer Reading Flow */}
      {showAnswer && (
        <div>
          {refused ? (
            <div className="flex items-start gap-3 p-4 rounded-2xl bg-amber-500/10 border border-amber-400/25 text-sm leading-relaxed">
              <ShieldAlert size={16} className="text-amber-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-[10px] font-mono tracking-wider text-amber-300 mb-1">
                  HONEST REFUSAL · 超出知识库证据边界
                </p>
                <p className="text-slate-100">
                  {renderTextWithUrl(answerText || '根据现有情报库无法回答此问题。', 'banner')}
                </p>
              </div>
            </div>
          ) : !answerReady ? (
            <div className="flex items-center gap-2.5 py-2 text-xs font-mono text-slate-400">
              {response.failed ? (
                <span className="text-rose-400">生成失败，可重试该问题（下方检索证据已保留）</span>
              ) : (
                <>
                  <span className="soc-dots">
                    <span />
                    <span />
                    <span />
                  </span>
                  正在结合召回证据与缝合表生成研判结论...
                </>
              )}
            </div>
          ) : (
            <AnswerText
              text={answerText}
              animated={animated}
              speed={demo ? 14 : 12}
              onCiteClick={onInspect ? handleCiteClick : undefined}
              onComplete={handleComplete}
            />
          )}

          {answerReady && (
            <div className="flex items-center gap-2 mt-4 flex-wrap">
              <button
                onClick={copyAnswer}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] text-[11px] text-slate-300 hover:text-white transition-colors"
              >
                {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                {copied ? '已复制' : '复制结论'}
              </button>
              <button
                onClick={handleExportBrief}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.04] hover:bg-sky-400/15 border border-white/[0.08] hover:border-sky-400/35 text-[11px] text-slate-300 hover:text-sky-200 transition-colors"
              >
                <Download size={12} />
                导出简报 (.md)
              </button>
            </div>
          )}
        </div>
      )}

      {/* 4. Structured CVE Cards */}
      {cards.length > 0 && (
        <div className="space-y-3 pt-1">
          <p className="text-[11px] font-mono uppercase tracking-widest text-slate-500">
            关联漏洞详情 ({cards.length})
          </p>
          <div className="space-y-3">
            {cards.map((card, i) => (
              <div key={`${card.cve_id}-${i}`} id={`card-${i}`}>
                <CVECard card={card} index={i} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Related Articles */}
      <RelatedPanel cveIds={cards.map((c) => c.cve_id)} />

      {/* 6. Evidence Feed */}
      {hits.length > 0 && (
        <div className="space-y-2.5 pt-1">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <button
              onClick={() => setHitsOpen((v) => !v)}
              className="inline-flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-widest text-slate-500 hover:text-slate-200 transition-colors"
            >
              <span>检索证据溯源 ({hits.length})</span>
              {hitsOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            </button>
            {hitsOpen && domainTabs.length > 1 && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setDomainFilter('all')}
                  className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase transition-colors ${
                    domainFilter === 'all'
                      ? 'bg-white/[0.1] text-white'
                      : 'text-slate-500 hover:text-slate-200'
                  }`}
                >
                  ALL {hits.length}
                </button>
                {domainTabs.map((d) => (
                  <button
                    key={d}
                    onClick={() => setDomainFilter(d)}
                    className={`px-2 py-0.5 rounded-md text-[10px] font-mono uppercase transition-colors ${
                      domainFilter === d
                        ? 'bg-white/[0.1] text-white'
                        : 'text-slate-500 hover:text-slate-200'
                    }`}
                  >
                    {d} {domainCounts[d]}
                  </button>
                ))}
              </div>
            )}
          </div>

          {hitsOpen && (
            <div className="space-y-2">
              {visibleHits.map(({ hit, idx }) =>
                !hit || typeof hit !== 'object' || !hit.title ? (
                  <div
                    key={idx}
                    className="p-2.5 rounded-xl border border-dashed border-white/[0.1] text-xs text-slate-500"
                  >
                    该条命中数据不完整，已降级显示
                  </div>
                ) : (
                  <div
                    key={idx}
                    onClick={() => onInspect?.({ kind: 'hit', index: idx, hit })}
                    className="cursor-pointer"
                  >
                    <HitCard hit={hit} index={idx} />
                  </div>
                )
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default memo(ChatMessage);

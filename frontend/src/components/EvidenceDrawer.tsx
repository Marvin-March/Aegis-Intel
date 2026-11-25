import { useEffect } from 'react';
import { X, ExternalLink, Sparkles, ShieldAlert } from 'lucide-react';
import type { NormalizedHit, VulnCard } from '../types/contract';
import CVECard from './CVECard';
import { DomainBadge } from './ui/Badge';

export type EvidenceSelection =
  | { kind: 'card'; index: number; card: VulnCard }
  | { kind: 'hit'; index: number; hit: NormalizedHit };

interface Props {
  item: EvidenceSelection | null;
  onClose: () => void;
}

/**
 * 右侧证据对照抽屉（Evidence Inspector）：点击 [n] / [卡n] 时平滑滑出，不打断正文阅读
 */
export default function EvidenceDrawer({ item, onClose }: Props) {
  useEffect(() => {
    if (!item) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [item, onClose]);

  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="fixed inset-0 bg-black/55 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <aside
        role="dialog"
        aria-modal="true"
        className="relative z-10 w-[460px] max-w-[92vw] h-full bg-[#090d16]/95 backdrop-blur-xl border-l border-white/[0.1] shadow-2xl flex flex-col animate-fade-in"
      >
        <header className="h-14 px-5 border-b border-white/[0.07] flex items-center justify-between gap-3 flex-shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="px-2 py-0.5 rounded-md bg-sky-500/15 border border-sky-400/35 text-[10px] font-mono text-sky-300">
              {item.kind === 'card' ? `卡${item.index + 1} · CVE 详情` : `证据 [${item.index + 1}]`}
            </span>
            <h3 className="text-xs font-semibold text-white truncate">
              {item.kind === 'card' ? item.card.cve_id : item.hit.title || '检索证据详情'}
            </h3>
          </div>
          <button
            onClick={onClose}
            aria-label="关闭证据抽屉"
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition-colors"
          >
            <X size={15} />
          </button>
        </header>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {item.kind === 'card' ? (
            <>
              <CVECard card={item.card} index={item.index} />
              {item.card.url && (
                <a
                  href={item.card.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.09] text-xs text-sky-300 transition-colors"
                >
                  查看原始漏洞公告
                  <ExternalLink size={12} />
                </a>
              )}
            </>
          ) : (
            <div className="space-y-4">
              <div className="flex items-center gap-2 flex-wrap">
                <DomainBadge domain={item.hit.domain} />
                {typeof item.hit.score === 'number' && (
                  <span className="px-2 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-[11px] font-mono text-sky-300 tabular-nums">
                    相关度 {item.hit.score.toFixed(3)}
                  </span>
                )}
                {item.hit.ai_related === 1 && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/15 border border-sky-400/30 text-[10px] font-mono text-sky-200">
                    <Sparkles size={10} />
                    AI 相关
                  </span>
                )}
              </div>

              <h4 className="text-base font-semibold text-white leading-snug">
                {item.hit.title || '未命名情报片段'}
              </h4>

              <div className="flex items-center gap-2 flex-wrap text-xs font-mono text-slate-400">
                <span>{item.hit.source || '未知来源'}</span>
                <span>·</span>
                <span>{item.hit.publish_time || '-'}</span>
              </div>

              {item.hit.cve_ids.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap">
                  <ShieldAlert size={13} className="text-rose-400" />
                  {item.hit.cve_ids.map((cve) => (
                    <span
                      key={cve}
                      className="px-2 py-0.5 rounded bg-rose-500/15 border border-rose-400/30 text-[11px] font-mono text-rose-200"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              )}

              <div className="rounded-xl bg-white/[0.03] border border-white/[0.08] p-4">
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-2">
                  召回原文片段
                </p>
                <p className="text-[13px] text-slate-200 leading-[1.75] whitespace-pre-wrap">
                  {item.hit.text}
                </p>
              </div>

              {item.hit.url && (
                <a
                  href={item.hit.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.09] text-xs text-sky-300 transition-colors"
                >
                  打开情报原文链接
                  <ExternalLink size={12} />
                </a>
              )}
            </div>
          )}
        </div>
      </aside>
    </div>
  );
}

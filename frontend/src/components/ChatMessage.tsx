import { useState, useEffect, useRef, useCallback, memo } from 'react';
import { User, Bot, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
import type { NormalizedQA, NormalizedHit, RelatedArticle } from '../types/contract';
import { getRelated } from '../api/client';
import Stepper from './Stepper';
import HitCard from './HitCard';
import CVECard from './CVECard';
import AnswerText, { renderTextWithUrl } from './AnswerText';

// 卡片区「相关分析文章」折叠面板：GET /related 关联推理（缝合表），点击展开时懒加载
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
    <div className="bg-soc-panel border border-soc-border p-3">
      <button
        onClick={toggle}
        className="flex items-center gap-2 w-full text-left text-xs text-soc-text-secondary hover:text-soc-primary transition-colors"
      >
        <span className="text-soc-text-muted font-mono text-[10px]">◆</span>
        {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        相关分析文章
        <span className="text-soc-text-muted tracking-wide">
          {uniqueIds.length} CVE
        </span>
      </button>
      {open && (
        <div className="mt-2.5 space-y-1.5 border-t border-soc-border pt-2.5">
          {loading ? (
            <p className="text-xs text-soc-text-muted flex items-center gap-2">
              <span className="soc-dots"><span /><span /><span /></span>
              缝合表反查中…
            </p>
          ) : (articles ?? []).length === 0 ? (
            <p className="text-xs text-soc-text-muted">未检索到关联文章</p>
          ) : (
            (articles ?? []).map((a, i) => (
              <a
                key={`${a.url}-${i}`}
                href={a.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-baseline gap-2 text-xs text-soc-text-secondary hover:text-soc-primary transition-colors animate-fade-slide-in"
                style={{ animationDelay: `${i * 60}ms` }}
              >
                <span className="font-mono text-[10px] text-purple-300/90 flex-shrink-0">{a.cve_id}</span>
                <span className="truncate">{a.title}</span>
                <span className="text-soc-text-muted flex-shrink-0 ml-auto font-mono text-[10px]">
                  {a.source} · {a.publish_time}
                </span>
              </a>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// 区块折叠标题：与 RelatedPanel 同款交互（点击展开/收起）
function SectionToggle({ label, open, onToggle }: { label: string; open: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      title={open ? '点击收起' : '点击展开'}
      className="flex items-center gap-2 w-full text-left group cursor-pointer"
    >
      <span className="soc-eyebrow group-hover:text-soc-primary transition-colors">{label}</span>
      {open ? (
        <ChevronUp size={14} className="text-soc-text-muted group-hover:text-soc-primary transition-colors" />
      ) : (
        <ChevronDown size={14} className="text-soc-text-muted group-hover:text-soc-primary transition-colors" />
      )}
    </button>
  );
}

interface Props {
  role: 'user' | 'assistant';
  content: string;
  response?: NormalizedQA;
  /** 仅「本轮最新」消息为 true：走检索可视化节奏；历史消息整段直出（K1） */
  animated?: boolean;
  /** 演示模式节奏：stepper 每步 1s、命中逐条入场、答案 60 字/秒、卡片停 2 秒 */
  demo?: boolean;
  /** 答案打字机完成回调（演示驱动器依赖它衔接下一幕） */
  onAnswerComplete?: () => void;
}

function ChatMessage({
  role,
  content,
  response,
  animated = false,
  demo = false,
  onAnswerComplete,
}: Props) {
  const [showAnswer, setShowAnswer] = useState(!animated);
  const [copied, setCopied] = useState(false);
  // 卡片组 / 命中区折叠开关（2026-10-16：默认展开，点标题收起——长回答时还屏幕给回答）
  const [cardsOpen, setCardsOpen] = useState(true);
  const [hitsOpen, setHitsOpen] = useState(true);
  // 稳定化回调引用，避免父组件重渲染导致打字机 effect 重启
  const completeRef = useRef(onAnswerComplete);
  completeRef.current = onAnswerComplete;
  const handleComplete = useCallback(() => completeRef.current?.(), []);

  // 复制答案（剪贴板 API，非安全上下文回退 execCommand）
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
        /* 忽略：复制失败不阻断交互 */
      }
      document.body.removeChild(ta);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }, [response]);

  useEffect(() => {
    if (!response || role !== 'assistant' || !animated) return;
    if (response.refused) {
      // K10：拒答场景不做 2s 空等，演示模式下等 stepper 走完再出
      const timer = setTimeout(() => setShowAnswer(true), demo ? 4000 : 0);
      return () => clearTimeout(timer);
    }
    const timer = setTimeout(() => setShowAnswer(true), demo ? 5000 : 2000);
    return () => clearTimeout(timer);
  }, [response, role, animated, demo]);

  // 拒答没有打字机，展示后即回调渲染完成
  useEffect(() => {
    if (!showAnswer || !response?.refused) return;
    const timer = setTimeout(() => handleComplete(), 400);
    return () => clearTimeout(timer);
  }, [showAnswer, response, handleComplete]);

  if (role === 'user') {
    return (
      <div className="flex justify-end mb-4">
        <div className="flex items-start gap-3 max-w-3xl animate-fade-slide-in">
          <div className="flex-1 bg-soc-hover border border-soc-border px-4 py-3">
            <p className="text-soc-text-primary whitespace-pre-wrap">{content}</p>
          </div>
          <div className="relative w-8 h-8 flex-shrink-0">
            <div className="absolute inset-0 border border-soc-text-muted/60 rotate-45" />
            <div className="absolute inset-0 flex items-center justify-center">
              <User size={15} className="text-soc-text-secondary" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Assistant message with full response rendering
  if (!response) return null;

  const hits: NormalizedHit[] = response.hits ?? [];
  const cards = response.cards ?? [];
  const refused = response.refused;
  const answerReady = response.answer !== undefined;
  const answerText = response.answer ?? '';

  const flagged = response.fabrications ?? 0;
  const steps = [
    {
      label: '意图路由',
      detail: `${response.route?.reason || '—'} → ${response.route?.branch ?? '—'}`,
      timing: response.route?.elapsed_ms,
    },
    {
      label: '向量召回',
      detail: `top-${hits.length}`,
    },
    {
      label: '缝合增强',
      detail: `${cards.length} 张卡片`,
    },
    {
      label: '智能体生成',
      detail: flagged > 0 ? `拦截 ${flagged}` : '✓',
    },
  ];

  // 入场节奏（仅 animated 消息生效）
  const hitDelay = (i: number) => (animated ? (demo ? i * 400 : i * 150) : 0);
  const cardDelay = (i: number) => {
    if (!animated) return 0;
    if (demo) return Math.max(3800, hits.length * 400 + 2000) + i * 250;
    return Math.max(800, hits.length * 150 + 400) + i * 120;
  };
  const bannerDelay = animated ? (demo ? 3600 : 0) : 0;

  const refusedBanner = (
    <div
      style={animated && bannerDelay > 0 ? { animationDelay: `${bannerDelay}ms` } : undefined}
      className={`flex items-start gap-3 p-3 bg-soc-warning/10 border border-soc-warning/40 ${
        animated ? 'animate-fade-slide-in' : ''
      }`}
    >
      <span className="w-1.5 h-1.5 mt-1.5 rotate-45 bg-soc-warning flex-shrink-0" />
      <p className="text-sm text-soc-text-primary leading-relaxed">
        {renderTextWithUrl(answerText || '根据现有情报库无法回答此问题。', 'banner')}
      </p>
    </div>
  );

  return (
    <div className="flex justify-start mb-7">
      <div className="flex items-start gap-3 w-full">
        {/* 助手标识：切角方章 + 脉冲环（生成中呼吸） */}
        <div className="relative w-8 h-8 flex-shrink-0">
          <div
            className={`absolute inset-0 border border-soc-primary/50 rotate-45 ${
              !answerReady && !refused ? 'animate-step-breathe' : ''
            }`}
          />
          <div className="absolute inset-0 flex items-center justify-center">
            <Bot size={15} className="text-soc-primary" />
          </div>
        </div>
        <div className="flex-1 space-y-4 min-w-0">
          {/* Stepper */}
          <Stepper steps={steps} activeIndex={3} stepMs={demo ? 1000 : 600} animate={animated} />

          {/* 缝合表漏洞卡片组（结构化，优先渲染；id 供 [卡n] 引用定位；可折叠） */}
          {cards.length > 0 && (
            <div className="space-y-3">
              <SectionToggle
                label={`SEWING · 缝合表关联漏洞卡片 ${cards.length} 张`}
                open={cardsOpen}
                onToggle={() => setCardsOpen((v) => !v)}
              />
              {cardsOpen &&
                cards.map((card, i) => (
                  <div
                    key={`${card.cve_id}-${i}`}
                    id={`card-${i}`}
                    style={animated && cardDelay(i) > 0 ? { animationDelay: `${cardDelay(i)}ms` } : undefined}
                    className={animated ? 'animate-fade-slide-in' : ''}
                  >
                    <CVECard card={card} animate={false} />
                  </div>
                ))}
            </div>
          )}

          {/* Hits（可折叠） */}
          {hits.length > 0 && (
            <div className="space-y-3">
              <SectionToggle
                label={`RETRIEVAL · 检索命中 ${hits.length} 条`}
                open={hitsOpen}
                onToggle={() => setHitsOpen((v) => !v)}
              />
              {hitsOpen &&
                hits.map((hit, idx) =>
                !hit || typeof hit !== 'object' || !hit.title ? (
                  // T4：hit 结构与契约不符 → 整卡降级渲染
                  <div
                    key={idx}
                    className="p-3 border border-dashed border-soc-border text-xs text-soc-text-muted"
                  >
                    该条命中数据不完整，已降级显示
                  </div>
                ) : (
                  <HitCard
                    key={idx}
                    hit={hit}
                    index={idx}
                    animate={animated}
                    delay={hitDelay(idx)}
                  />
                )
              )}
            </div>
          )}

          {/* 关联文章反查（/related，点击展开懒加载） */}
          <RelatedPanel cveIds={cards.map((c) => c.cve_id)} />

          {/* Answer */}
          {showAnswer && (
            <div className="soc-glass p-4">
              {refused ? (
                refusedBanner
              ) : !answerReady ? (
                // 两段式中间态：检索已出、答案未回
                <div className="flex items-center gap-2.5 p-3 text-sm text-soc-text-muted">
                  {response.failed ? (
                    <>生成失败，可重试该问题</>
                  ) : (
                    <>
                      <span className="soc-dots"><span /><span /><span /></span>
                      智能体生成中…
                    </>
                  )}
                </div>
              ) : (
                <AnswerText
                  text={answerText}
                  animated={animated}
                  speed={demo ? 16 : 15}
                  onComplete={handleComplete}
                />
              )}

              {/* Quality Badges（答案阶段就绪后展示） */}
              {answerReady && (
                <div className="flex items-center gap-2 mt-4 pt-4 border-t border-soc-border flex-wrap">
                  <span
                    className={`px-2 py-1 text-[11px] font-mono border ${
                      flagged === 0
                        ? 'border-soc-success/50 text-soc-success'
                        : 'border-soc-warning/50 text-soc-warning'
                    }`}
                  >
                    {flagged === 0 ? 'FABRICATE 0 ✓' : `FABRICATE ${flagged}`}
                  </span>
                  {response.elapsed_s !== undefined && (
                    <span className="px-2 py-1 border border-soc-border text-soc-text-muted text-[11px] font-mono">
                      ELAPSED {response.elapsed_s.toFixed(1)}s
                    </span>
                  )}
                  <button
                    onClick={copyAnswer}
                    aria-label="复制答案"
                    className={`ml-auto px-2 py-1 border text-[11px] font-mono transition-colors flex items-center gap-1.5 ${
                      copied
                        ? 'border-soc-success/50 text-soc-success'
                        : 'border-soc-border text-soc-text-muted hover:text-soc-primary hover:border-soc-primary/50'
                    }`}
                  >
                    {copied ? <Check size={11} /> : <Copy size={11} />}
                    {copied ? '已复制' : 'COPY'}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// React.memo：会话内输入/演示打字时不重渲染历史消息（含全部命中卡与 CVE 卡）
export default memo(ChatMessage);

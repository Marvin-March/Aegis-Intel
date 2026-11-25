import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ArrowUp, ChevronDown, Play, ShieldCheck, Search, FileText, ArrowUpRight } from 'lucide-react';
import { ask, searchOnly } from '../api/client';
import type { Session, Message } from '../utils/storage';
import type { NormalizedQA, HistoryTurn } from '../types/contract';
import {
  getSession,
  createSession,
  addMessage,
  updateSession,
  updateMessage,
} from '../utils/storage';
import ChatMessage from './ChatMessage';
import DemoOverlay from './DemoOverlay';
import EvidenceDrawer, { type EvidenceSelection } from './EvidenceDrawer';
import { toast } from './Toast';
import { useDemoPlayer } from '../hooks/useDemoPlayer';

const quickChips = [
  { tag: 'CVE 点查', label: 'CVE-2026-59822', query: 'CVE-2026-59822 是什么漏洞？' },
  { tag: '组件排查', label: 'vLLM 已知漏洞', query: 'vLLM 有哪些已知漏洞？' },
  { tag: '修复方案', label: 'Dify SSRF 修复', query: 'Dify 的 SSRF 漏洞怎么修？' },
  { tag: '事件溯源', label: 'Copilot 安全事件', query: '微软 Copilot 出过什么安全事件？' },
  { tag: '论文检索', label: 'LLM Agent 安全论文', query: '有哪些关于 LLM Agent 安全的论文？' },
  { tag: '边界校验', label: '诚实拒答演示', query: 'CVE-2099-00001 是什么？' },
];

const SEARCH_STAGES = ['编码查询向量...', '向量召回 top-8...', '缝合表关联增强...'];
const ANSWER_STAGE = '智能体综合生成与编号校验...';

function cveFromResponse(resp: any): string | undefined {
  if (typeof resp?.route === 'string') {
    const m = resp.route.match(/CVE-\d{4}-\d{4,7}/i);
    if (m) return m[0].toUpperCase();
  }
  return resp?.cards?.[0]?.cve_id;
}

function buildHistoryTail(sessionId: string): HistoryTurn[] {
  const messages = (getSession(sessionId)?.messages ?? []).slice(-6);
  return messages.map((m) => {
    const cve = m.role === 'assistant' ? cveFromResponse(m.response) : undefined;
    return m.role === 'user'
      ? { role: 'user' as const, content: m.content }
      : {
          role: 'assistant' as const,
          content: m.content.slice(0, 200),
          ...(cve ? { cve_id: cve } : {}),
        };
  });
}

interface Props {
  sessions: Session[];
  currentSessionId: string | null;
  onSessionsChange: () => void;
  onSelectSession: (id: string) => void;
  onCreateSession: () => string;
  pendingQuery: { id: number; query: string } | null;
  onConsumePendingQuery: () => void;
}

export default function AskTab({
  sessions,
  currentSessionId,
  onSessionsChange,
  onSelectSession,
  onCreateSession,
  pendingQuery,
  onConsumePendingQuery,
}: Props) {
  const [animatedMsgId, setAnimatedMsgId] = useState<string | null>(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState<'search' | 'answer'>('search');
  const [waitingSeconds, setWaitingSeconds] = useState(0);
  const [stageIdx, setStageIdx] = useState(0);
  const [evidence, setEvidence] = useState<EvidenceSelection | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const scrollBoxRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [showScrollBottom, setShowScrollBottom] = useState(false);
  const waitingIntervalRef = useRef<number>();
  const renderDoneRef = useRef<(() => void) | null>(null);
  const handleAnswerComplete = useCallback(() => renderDoneRef.current?.(), []);
  const prevSessionRef = useRef<string | null>(null);
  const demoActiveRef = useRef(false);

  const currentSession = sessions.find((s) => s.id === currentSessionId) ?? null;

  useEffect(() => {
    return () => {
      if (waitingIntervalRef.current) clearInterval(waitingIntervalRef.current);
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [currentSession?.messages]);

  const handleScroll = () => {
    const el = scrollBoxRef.current;
    if (!el) return;
    setShowScrollBottom(el.scrollHeight - el.scrollTop - el.clientHeight > 220);
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = !!target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
      if (e.key === '/' && !typing) {
        e.preventDefault();
        textareaRef.current?.focus();
      } else if (e.key === 'Escape' && document.activeElement === textareaRef.current) {
        textareaRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (!loading) {
      setStageIdx(0);
      return;
    }
    const interval = setInterval(() => setStageIdx((i) => i + 1), 2500);
    return () => clearInterval(interval);
  }, [loading]);

  const handleSend = useCallback(
    async (
      queryText?: string,
      opts?: { forceMock?: boolean; onRenderDone?: () => void }
    ) => {
      const query = (queryText ?? input).trim();
      if (!query || loading) return;
      if (!opts?.forceMock && demoActiveRef.current) return;

      const targetSessionId = currentSessionId || onCreateSession();

      setInput('');
      setLoading(true);
      setPhase('search');
      setWaitingSeconds(0);

      const history = buildHistoryTail(targetSessionId);

      const userMsg: Message = {
        id: `msg_${Date.now()}`,
        role: 'user',
        content: query,
        timestamp: new Date().toISOString(),
      };
      addMessage(targetSessionId, userMsg);
      onSessionsChange();

      const assistantId = `msg_${Date.now() + 1}`;
      waitingIntervalRef.current = window.setInterval(() => {
        setWaitingSeconds((prev) => prev + 1);
      }, 1000);

      let inserted = false;
      let searchResult: NormalizedQA | null = null;

      try {
        const req = { query, k: 8, history };
        searchResult = await searchOnly(req, { forceMock: opts?.forceMock });
        const assistantMsg: Message = {
          id: assistantId,
          role: 'assistant',
          content: '',
          timestamp: new Date().toISOString(),
          response: searchResult,
        };
        addMessage(targetSessionId, assistantMsg);
        inserted = true;
        setAnimatedMsgId(assistantId);
        onSessionsChange();

        setPhase('answer');
        const full = await ask({ ...req, with_answer: true }, { forceMock: opts?.forceMock });
        updateMessage(targetSessionId, assistantId, {
          content: full.answer ?? '',
          response: full,
        });
        onSessionsChange();
      } catch (error) {
        toast.error(error instanceof Error ? error.message : '请求失败');
        if (inserted && searchResult) {
          updateMessage(targetSessionId, assistantId, {
            response: { ...searchResult, failed: true },
          });
          onSessionsChange();
        }
        opts?.onRenderDone?.();
      } finally {
        setLoading(false);
        setPhase('search');
        setWaitingSeconds(0);
        if (waitingIntervalRef.current) clearInterval(waitingIntervalRef.current);
      }
    },
    [input, loading, currentSessionId, onCreateSession, onSessionsChange]
  );

  // 消费来自看板下钻或 ⌘K 命令面板的跨页研判请求
  useEffect(() => {
    if (!pendingQuery || loading) return;
    const q = pendingQuery.query;
    onConsumePendingQuery();
    void handleSend(q);
  }, [pendingQuery, loading, onConsumePendingQuery, handleSend]);

  const demoSend = (query: string): Promise<void> =>
    new Promise((resolve) => {
      let settled = false;
      const once = () => {
        if (!settled) {
          settled = true;
          resolve();
        }
      };
      renderDoneRef.current = once;
      void handleSend(query, { forceMock: true, onRenderDone: once });
    });

  const demo = useDemoPlayer({ setInput, send: (q) => demoSend(q) });

  useEffect(() => {
    demoActiveRef.current = demo.active;
  }, [demo.active]);

  const enterDemo = () => {
    prevSessionRef.current = currentSessionId;
    const demoSession = createSession();
    updateSession(demoSession.id, { title: '演示模式' });
    onSessionsChange();
    onSelectSession(demoSession.id);
    setAnimatedMsgId(null);
    demo.enter();
  };

  const exitDemo = () => {
    demo.exit();
    const prev = prevSessionRef.current;
    if (prev && getSession(prev)) {
      onSelectSession(prev);
    } else {
      onCreateSession();
    }
    setAnimatedMsgId(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void handleSend();
    }
  };

  const stageText =
    phase === 'answer' ? ANSWER_STAGE : SEARCH_STAGES[stageIdx % SEARCH_STAGES.length];

  const messages = currentSession?.messages ?? [];

  return (
    <div className="h-full flex flex-col min-h-0 relative">
      {/* Top Sub-Action Strip (Demo trigger only when needed) */}
      {!demo.active && (
        <div className="flex items-center justify-end px-6 pt-3 pb-1 flex-shrink-0">
          <button
            onClick={enterDemo}
            className="h-7 px-3 rounded-full bg-white/[0.04] hover:bg-white/[0.09] border border-white/[0.09] text-[11px] text-slate-300 hover:text-white inline-flex items-center gap-1.5 transition-colors"
          >
            <Play size={11} className="text-sky-400" />
            演示模式
          </button>
        </div>
      )}

      {/* Open Airy Reading Stream */}
      <div
        ref={scrollBoxRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-5 sm:px-10 py-4 min-h-0"
      >
        {messages.length === 0 ? (
          <div className="max-w-3xl mx-auto h-full flex flex-col justify-center py-8 animate-fade-in">
            <div className="mb-7">
              <p className="text-[11px] font-mono tracking-widest text-sky-400 uppercase mb-2">
                Aegis Intel Agent
              </p>
              <h2 className="text-2xl font-semibold text-white tracking-tight">
                输入 CVE 编号、AI 组件或安全问题开始研判
              </h2>
              <p className="text-sm text-slate-400 mt-2 leading-relaxed">
                自动执行六路意图路由与两段式检索，优先召回结构化漏洞卡片并附带编号级引用溯源。
              </p>
              <div className="flex flex-wrap gap-4 mt-4 text-xs font-mono text-slate-400">
                <span className="inline-flex items-center gap-1.5">
                  <Search size={12} className="text-sky-400" />
                  SQL 精准点查
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <FileText size={12} className="text-indigo-400" />
                  语义召回 & 论文检索
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <ShieldCheck size={12} className="text-emerald-400" />
                  编号防幻觉校验
                </span>
              </div>
            </div>

            {!demo.active && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                {quickChips.map((chip) => (
                  <button
                    key={chip.label}
                    onClick={() => void handleSend(chip.query)}
                    disabled={loading}
                    className="group text-left p-3.5 rounded-xl bg-white/[0.03] border border-white/[0.08] hover:border-sky-400/40 hover:bg-white/[0.06] transition-all disabled:opacity-50"
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="text-[10px] font-mono text-sky-300">{chip.tag}</span>
                      <ArrowUpRight
                        size={12}
                        className="text-slate-500 group-hover:text-sky-300 transition-colors"
                      />
                    </div>
                    <p className="text-xs font-medium text-white mb-0.5">{chip.label}</p>
                    <p className="text-[11px] text-slate-400 line-clamp-1">{chip.query}</p>
                  </button>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="max-w-3xl mx-auto space-y-10 pb-6">
            {messages.map((msg, i) => {
              const prevUserQuery =
                msg.role === 'assistant' && i > 0 && messages[i - 1].role === 'user'
                  ? messages[i - 1].content
                  : '';
              return (
                <ChatMessage
                  key={msg.id}
                  role={msg.role}
                  content={msg.content}
                  userQuery={prevUserQuery}
                  response={msg.response}
                  animated={msg.id === animatedMsgId}
                  demo={demo.active}
                  onInspect={setEvidence}
                  onAnswerComplete={
                    msg.id === animatedMsgId ? handleAnswerComplete : undefined
                  }
                />
              );
            })}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Scroll to Bottom */}
      {showScrollBottom && (
        <button
          onClick={scrollToBottom}
          aria-label="回到底部"
          className="absolute right-6 bottom-[126px] z-10 w-8 h-8 rounded-full flex items-center justify-center bg-[#0d121f]/90 border border-white/[0.12] text-slate-300 hover:text-white shadow-xl transition-colors"
        >
          <ChevronDown size={15} />
        </button>
      )}

      {/* Floating Frosted Command Composer */}
      <div className="flex-shrink-0 px-5 sm:px-10 pb-5 pt-2 bg-gradient-to-t from-[#05060a] via-[#05060a]/90 to-transparent">
        <div className="max-w-3xl mx-auto">
          {!demo.active && messages.length > 0 && (
            <div className="flex gap-1.5 mb-2.5 overflow-x-auto pb-0.5">
              {quickChips.map((chip) => (
                <button
                  key={chip.label}
                  onClick={() => setInput(chip.query)}
                  disabled={loading}
                  className="px-3 py-1 rounded-full bg-white/[0.03] border border-white/[0.07] hover:border-sky-400/40 hover:bg-sky-400/10 text-[11px] text-slate-400 hover:text-sky-200 transition-all whitespace-nowrap flex-shrink-0"
                >
                  {chip.label}
                </button>
              ))}
            </div>
          )}

          {loading && (
            <div className="flex items-center gap-2 mb-2 text-[11px] font-mono text-slate-300">
              <span className="soc-dots">
                <span />
                <span />
                <span />
              </span>
              <span>{stageText}</span>
              <span className="text-sky-300 tabular-nums">{waitingSeconds}s</span>
            </div>
          )}

          <div className="laser-rim rounded-2xl bg-[#0b0e17]/85 backdrop-blur-xl border border-white/[0.12] focus-within:border-sky-400/50 focus-within:shadow-focus-cyan transition-all p-2 flex items-end gap-2 shadow-2xl">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="输入 CVE 编号、AI 组件或安全问题… (Enter 发送 · / 聚焦 · ⌘K 命令面板)"
              disabled={loading || demo.active}
              rows={2}
              className="flex-1 bg-transparent px-3 py-1.5 text-[14px] text-white placeholder:text-slate-500 focus:outline-none resize-none leading-relaxed disabled:opacity-60"
            />
            <button
              onClick={() => void handleSend()}
              disabled={loading || !input.trim() || demo.active}
              aria-label="发送问题"
              className="h-9 px-4 rounded-xl bg-white hover:bg-sky-100 text-slate-950 font-semibold text-xs inline-flex items-center justify-center gap-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed flex-shrink-0"
            >
              {loading ? (
                <>
                  <span className="soc-dots soc-dots-dark">
                    <span />
                    <span />
                    <span />
                  </span>
                  <span className="font-mono tabular-nums">{waitingSeconds}s</span>
                </>
              ) : (
                <>
                  <span>研判</span>
                  <ArrowUp size={14} />
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Demo Bar */}
      {demo.active && (
        <div className="px-5 pb-3">
          <DemoOverlay
            current={demo.current}
            playing={demo.playing}
            onPlayScene={(i) => demo.play(i)}
            onPlayAll={() => demo.play()}
            onExit={exitDemo}
          />
        </div>
      )}

      {/* Right-Side Evidence Inspector Drawer */}
      <EvidenceDrawer item={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}

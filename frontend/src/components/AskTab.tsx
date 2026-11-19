import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Send, ChevronDown } from 'lucide-react';
import { ask, searchOnly } from '../api/client';
import type { Session, Message } from '../utils/storage';
import type { NormalizedQA, HistoryTurn } from '../types/contract';
import {
  getSessions,
  getCurrentSessionId,
  createSession,
  getSession,
  deleteSession,
  addMessage,
  setCurrentSessionId,
  updateSession,
  updateMessage,
} from '../utils/storage';
import SessionList from './SessionList';
import ChatMessage from './ChatMessage';
import DemoOverlay from './DemoOverlay';
import AskHero from './AskHero';
import { toast } from './Toast';
import { useDemoPlayer } from '../hooks/useDemoPlayer';

// 预置快捷问题（便于演示快速开始）
const quickChips = [
  { label: 'vLLM 已知漏洞', query: 'vLLM 有哪些已知漏洞？' },
  { label: 'CVE-2026-59822', query: 'CVE-2026-59822 是什么漏洞？' },
  { label: 'Dify SSRF', query: 'Dify 的 SSRF 漏洞怎么修？' },
  { label: 'Copilot 安全事件', query: '微软 Copilot 出过什么安全事件？' },
  { label: 'LLM Agent 论文', query: '有哪些关于 LLM Agent 安全的论文？' },
  { label: '拒答演示', query: 'CVE-2024-3094 是什么？' },
];

// loading 阶段文案：检索阶段轮换，生成阶段固定
const SEARCH_STAGES = ['嵌入查询向量…', '向量召回 top-8…', '缝合表增强…'];
const ANSWER_STAGE = '智能体生成答案…';

// 多轮上下文：快照本会话最近 6 条消息为 HistoryTurn[]。
// assistant 轮附上该轮响应锁定实体，后端 search.py 对指代短句做实体继承。
// cve_id 提取优先级（2026-10-15 加固）：① route 里的编号（"sql点查 CVE-xxxx" 是后端
// 点查的真凭实据，最权威）→ ② 卡片 cards[0].cve_id（向量/缝合轮兜底）。防止 route 点查
// 命中正确 CVE 时卡片数组顺序被缝合干扰而错位。
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

// 空态内联 SVG：情报网络图（节点 + 连线，绘制动画 + 节点脉动）
function EmptyIllustration() {
  const nodes = [
    { x: 30, y: 88 },
    { x: 58, y: 46 },
    { x: 96, y: 70 },
    { x: 122, y: 34 },
    { x: 76, y: 16 },
  ];
  const links: Array<[number, number]> = [
    [0, 1],
    [1, 2],
    [2, 0],
    [1, 3],
    [2, 3],
    [1, 4],
    [4, 3],
  ];
  return (
    <svg
      width="150"
      height="110"
      viewBox="0 0 150 110"
      fill="none"
      className="mb-6 animate-gentle-float"
    >
      {/* 连线（逐条绘制） */}
      {links.map(([a, b], i) => (
        <line
          key={i}
          x1={nodes[a].x}
          y1={nodes[a].y}
          x2={nodes[b].x}
          y2={nodes[b].y}
          stroke="#38bdf8"
          strokeWidth="1"
          opacity="0.4"
          className="soc-draw-line"
          style={{ ['--dash' as string]: '120', animationDelay: `${i * 160}ms` }}
        />
      ))}
      {/* 节点（脉动） */}
      {nodes.map((n, i) => (
        <g key={i}>
          <circle
            cx={n.x}
            cy={n.y}
            r="2.6"
            fill={i === 1 ? '#38bdf8' : '#64748b'}
            style={{ animation: `node-pulse 3s ease-in-out ${i * 0.5}s infinite` }}
          />
          {/* 主节点外环 */}
          {i === 1 && (
            <circle cx={n.x} cy={n.y} r="7" stroke="#38bdf8" strokeWidth="1" opacity="0.35">
              <animate attributeName="r" values="5;9;5" dur="3s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.4;0.12;0.4" dur="3s" repeatCount="indefinite" />
            </circle>
          )}
        </g>
      ))}
    </svg>
  );
}

export default function AskTab() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [currentSessionId, setCurrentSession] = useState<string | null>(null);
  const [animatedMsgId, setAnimatedMsgId] = useState<string | null>(null);
  // 会话侧边栏收起状态持久化（localStorage，刷新保持）
  const [sessionsCollapsed, setSessionsCollapsed] = useState<boolean>(
    () => localStorage.getItem('ask.sessionsCollapsed') === '1'
  );
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState<'search' | 'answer'>('search');
  const [waitingSeconds, setWaitingSeconds] = useState(0);
  const [stageIdx, setStageIdx] = useState(0);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const scrollBoxRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [showScrollBottom, setShowScrollBottom] = useState(false);
  const waitingIntervalRef = useRef<number>();
  // 演示驱动：当前这条消息渲染完成时通过它兑现 demoSend 的 Promise
  const renderDoneRef = useRef<(() => void) | null>(null);
  // 稳定回调引用：配合 ChatMessage 的 memo，避免输入时重渲染全部历史消息
  const handleAnswerComplete = useCallback(() => renderDoneRef.current?.(), []);
  const prevSessionRef = useRef<string | null>(null);
  const demoActiveRef = useRef(false);

  // K9：会话从 state 派生，不在渲染体里反复读 localStorage
  const currentSession = sessions.find((s) => s.id === currentSessionId) ?? null;

  useEffect(() => {
    setSessions(getSessions());
    const savedId = getCurrentSessionId();
    if (savedId && getSession(savedId)) {
      setCurrentSession(savedId);
    } else {
      handleCreateSession();
    }
  }, []);

  // K8：卸载时清理等待计时 interval
  useEffect(() => {
    return () => {
      if (waitingIntervalRef.current) {
        clearInterval(waitingIntervalRef.current);
      }
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [currentSession?.messages]);

  // 滚动位置感知：离底部较远时显示「回到底部」浮动按钮
  const handleScroll = () => {
    const el = scrollBoxRef.current;
    if (!el) return;
    setShowScrollBottom(el.scrollHeight - el.scrollTop - el.clientHeight > 220);
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // 键盘快捷键：Ctrl+K 或 / 聚焦输入框，Esc 失焦（输入框内除外）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = !!target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
      if ((e.ctrlKey && e.key.toLowerCase() === 'k') || (e.key === '/' && !typing)) {
        e.preventDefault();
        textareaRef.current?.focus();
      } else if (e.key === 'Escape' && document.activeElement === textareaRef.current) {
        textareaRef.current?.blur();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // loading 阶段文案轮换
  useEffect(() => {
    if (!loading) {
      setStageIdx(0);
      return;
    }
    const interval = setInterval(() => {
      setStageIdx((i) => i + 1);
    }, 2500);
    return () => clearInterval(interval);
  }, [loading]);

  const handleToggleSessions = () => {
    setSessionsCollapsed((prev) => {
      localStorage.setItem('ask.sessionsCollapsed', prev ? '0' : '1');
      return !prev;
    });
  };

  const handleCreateSession = () => {
    const newSession = createSession();
    setSessions(getSessions());
    setCurrentSession(newSession.id);
    setAnimatedMsgId(null);
  };

  const handleSelectSession = (id: string) => {
    setCurrentSession(id);
    setCurrentSessionId(id);
    setAnimatedMsgId(null);
  };

  const handleDeleteSession = (id: string) => {
    deleteSession(id);
    setSessions(getSessions());
    if (currentSessionId === id) {
      const remaining = getSessions();
      if (remaining.length > 0) {
        handleSelectSession(remaining[0].id);
      } else {
        handleCreateSession();
      }
    }
  };

  // 两段式问答：/search 先渲染检索可视化，/ask 回填答案（对接说明推荐交互流）
  const handleSend = async (
    queryText?: string,
    opts?: { forceMock?: boolean; onRenderDone?: () => void }
  ) => {
    const query = (queryText ?? input).trim();
    if (!query || loading || !currentSessionId) return;
    // 演示播放期间不接受手动发送（演示自身的发送带 forceMock 标记放行）
    if (!opts?.forceMock && demoActiveRef.current) return;

    setInput('');
    setLoading(true);
    setPhase('search');
    setWaitingSeconds(0);

    // 多轮上下文：先于本轮消息入库快照历史（推进时不含本轮追问本身）
    const history = buildHistoryTail(currentSessionId);

    const userMsg: Message = {
      id: `msg_${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toISOString(),
    };
    addMessage(currentSessionId, userMsg);
    setSessions(getSessions());

    const assistantId = `msg_${Date.now() + 1}`;
    waitingIntervalRef.current = window.setInterval(() => {
      setWaitingSeconds((prev) => prev + 1);
    }, 1000);

    let inserted = false;
    let searchResult: NormalizedQA | null = null;

    try {
      const req = {
        query,
        k: 8,
        history,
      };

      // 阶段一：检索（路由 + top-k 分数条 + 卡片先出）
      searchResult = await searchOnly(req, { forceMock: opts?.forceMock });
      const assistantMsg: Message = {
        id: assistantId,
        role: 'assistant',
        content: '',
        timestamp: new Date().toISOString(),
        response: searchResult,
      };
      addMessage(currentSessionId, assistantMsg);
      inserted = true;
      // 仅这条最新消息走动画节奏（K1）
      setAnimatedMsgId(assistantId);
      setSessions(getSessions());

      // 阶段二：智能体生成答案
      setPhase('answer');
      const full = await ask({ ...req, with_answer: true }, { forceMock: opts?.forceMock });
      updateMessage(currentSessionId, assistantId, {
        content: full.answer ?? '',
        response: full,
      });
      setSessions(getSessions());
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '请求失败');
      if (inserted && searchResult) {
        // 检索已出、生成失败：消息保留检索结果并标记失败
        updateMessage(currentSessionId, assistantId, {
          response: { ...searchResult, failed: true },
        });
        setSessions(getSessions());
      }
      opts?.onRenderDone?.();
    } finally {
      setLoading(false);
      setPhase('search');
      setWaitingSeconds(0);
      if (waitingIntervalRef.current) {
        clearInterval(waitingIntervalRef.current);
      }
    }
  };

  // 演示用发送：强制 mock 数据源；Promise 在整轮问答渲染完成后兑现
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
    // 演示走独立会话，不污染用户历史
    const demoSession = createSession();
    updateSession(demoSession.id, { title: '演示模式' });
    setSessions(getSessions());
    setCurrentSession(demoSession.id);
    setAnimatedMsgId(null);
    demo.enter();
  };

  const exitDemo = () => {
    demo.exit();
    const prev = prevSessionRef.current;
    if (prev && getSession(prev)) {
      setCurrentSession(prev);
      setCurrentSessionId(prev);
    } else {
      handleCreateSession();
    }
    setAnimatedMsgId(null);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const stageText =
    phase === 'answer' ? ANSWER_STAGE : SEARCH_STAGES[stageIdx % SEARCH_STAGES.length];

  return (
    <div className="flex flex-col h-[calc(100vh-180px)] gap-4">
      {/* Hero 头 + 演示模式入口 */}
      <AskHero demo={demo.active} onEnterDemo={enterDemo} />

      <div className="flex gap-6 flex-1 min-h-0">
        {/* 会话侧边栏（可收起；演示模式整块隐藏，全屏专注布局） */}
        {!demo.active && (
          <div
            className={`flex-shrink-0 min-h-0 transition-[width] duration-300 ease-in-out overflow-hidden ${
              sessionsCollapsed ? 'w-12' : 'w-72'
            }`}
          >
            <SessionList
              sessions={sessions}
              currentId={currentSessionId}
              collapsed={sessionsCollapsed}
              onToggle={handleToggleSessions}
              onSelect={handleSelectSession}
              onCreate={handleCreateSession}
              onDelete={handleDeleteSession}
            />
          </div>
        )}

        {/* Chat Area */}
        <div className="flex-1 flex flex-col soc-glass min-h-0 relative">
          {/* Messages */}
          <div
            ref={scrollBoxRef}
            onScroll={handleScroll}
            className="flex-1 overflow-y-auto p-6 min-h-0"
          >
            {!currentSession || currentSession.messages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center animate-panel-reveal">
                <EmptyIllustration />
                <p className="text-lg tracking-[0.2em] text-soc-text-primary mb-2">开始提问</p>
                <p className="text-xs tracking-[0.12em] text-soc-text-muted mb-2">
                  SUPPORT · CVE 点查 / 语义检索 / 论文检索
                </p>
                <div className="w-16 h-px bg-soc-border mb-6" />
                {!demo.active && (
                  <div className="flex gap-2 flex-wrap justify-center">
                    {quickChips.slice(0, 3).map((chip) => (
                      <button
                        key={chip.label}
                        onClick={() => handleSend(chip.query)}
                        disabled={loading}
                        className="soc-btn-ghost px-3 py-1.5 text-sm disabled:opacity-50"
                      >
                        {chip.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <>
                {currentSession.messages.map((msg) => (
                  <ChatMessage
                    key={msg.id}
                    role={msg.role}
                    content={msg.content}
                    response={msg.response}
                    animated={msg.id === animatedMsgId}
                    demo={demo.active}
                    onAnswerComplete={
                      msg.id === animatedMsgId ? handleAnswerComplete : undefined
                    }
                  />
                ))}
                <div ref={messagesEndRef} />
              </>
            )}
          </div>

          {/* 回到底部浮动按钮：离底部较远时出现 */}
          {showScrollBottom && (
            <button
              onClick={scrollToBottom}
              aria-label="回到底部"
              className="absolute right-5 bottom-[148px] z-10 w-8 h-8 flex items-center justify-center border border-soc-border bg-soc-panel/95 text-soc-text-secondary hover:text-soc-primary hover:border-soc-primary/50 hover:shadow-[0_0_16px_-4px_rgba(34,211,238,0.5)] transition-all animate-fade-slide-in"
            >
              <ChevronDown size={14} />
            </button>
          )}

          {/* Input */}
          <div className="border-t border-soc-border p-4">
            {!demo.active && (
              <div className="flex gap-2 mb-2 flex-wrap items-center">
                {quickChips.map((chip) => (
                  <button
                    key={chip.label}
                    onClick={() => setInput(chip.query)}
                    disabled={loading}
                    className="px-2 py-1 border border-transparent hover:border-soc-border text-soc-text-muted hover:text-soc-text-secondary text-xs tracking-wide transition-all disabled:opacity-50"
                  >
                    {chip.label}
                  </button>
                ))}
                <span className="flex-1" />
              </div>
            )}
            {loading && (
              <p className="text-xs text-soc-text-muted mb-2 flex items-center gap-2.5 tracking-wide">
                <span className="soc-dots"><span /><span /><span /></span>
                {stageText}
                <span className="font-mono text-soc-primary/80">已等待 {waitingSeconds}s</span>
              </p>
            )}
            <div className="flex gap-2">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="输入问题... (Enter 发送 / Shift+Enter 换行 / Ctrl+K 聚焦)"
                disabled={loading || demo.active}
                className="flex-1 px-4 py-3 bg-soc-bg border border-soc-border text-soc-text-primary placeholder-soc-text-muted resize-none focus:outline-none focus:border-soc-primary/60 transition-colors disabled:opacity-50"
                rows={3}
              />
              <button
                onClick={() => handleSend()}
                disabled={loading || !input.trim() || demo.active}
                aria-label="发送问题"
                className="soc-btn-primary px-6 font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? (
                  <>
                    <span className="soc-dots soc-dots-dark"><span /><span /><span /></span>
                    <span className="text-sm font-mono">{waitingSeconds}s</span>
                  </>
                ) : (
                  <Send size={18} />
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 演示控制条 + 顶部水印 */}
      {demo.active && (
        <DemoOverlay
          current={demo.current}
          playing={demo.playing}
          onPlayScene={(i) => demo.play(i)}
          onPlayAll={() => demo.play()}
          onExit={exitDemo}
        />
      )}
    </div>
  );
}

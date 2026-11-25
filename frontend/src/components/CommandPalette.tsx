import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Search,
  Sparkles,
  BarChart3,
  Radar,
  MessageSquare,
  Plus,
  CornerDownLeft,
} from 'lucide-react';
import type { Session } from '../utils/storage';

export type WorkspaceTab = 'ask' | 'stats' | 'monitor';

interface Props {
  open: boolean;
  onClose: () => void;
  sessions: Session[];
  onSwitchTab: (tab: WorkspaceTab) => void;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onQuickQuery: (query: string) => void;
}

interface CommandItem {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon: 'ask' | 'stats' | 'monitor' | 'session' | 'new' | 'query';
  run: () => void;
}

/**
 * Raycast / Linear 风格全局 ⌘K 命令面板
 */
export default function CommandPalette({
  open,
  onClose,
  sessions,
  onSwitchTab,
  onSelectSession,
  onNewSession,
  onQuickQuery,
}: Props) {
  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!open) return;
    setQuery('');
    setActiveIdx(0);
    window.setTimeout(() => inputRef.current?.focus(), 20);
  }, [open]);

  const items = useMemo<CommandItem[]>(() => {
    const q = query.trim();
    const list: CommandItem[] = [];

    if (q) {
      list.push({
        id: 'direct-query',
        group: '立即研判',
        label: `向 Aegis Agent 提问：「${q}」`,
        hint: 'Enter',
        icon: 'query',
        run: () => {
          onQuickQuery(q);
          onClose();
        },
      });
    }

    const base: CommandItem[] = [
      {
        id: 'tab-ask',
        group: '工作台导航',
        label: '切换到 智能问答 (Intel QA)',
        hint: '⌘1',
        icon: 'ask',
        run: () => {
          onSwitchTab('ask');
          onClose();
        },
      },
      {
        id: 'tab-stats',
        group: '工作台导航',
        label: '切换到 数据看板 (Analytics)',
        hint: '⌘2',
        icon: 'stats',
        run: () => {
          onSwitchTab('stats');
          onClose();
        },
      },
      {
        id: 'tab-monitor',
        group: '工作台导航',
        label: '切换到 情报监测 (Collectors)',
        hint: '⌘3',
        icon: 'monitor',
        run: () => {
          onSwitchTab('monitor');
          onClose();
        },
      },
      {
        id: 'new-session',
        group: '快捷操作',
        label: '新建研判会话',
        icon: 'new',
        run: () => {
          onNewSession();
          onClose();
        },
      },
      ...sessions.slice(0, 6).map((s) => ({
        id: `session-${s.id}`,
        group: '最近会话',
        label: s.title,
        hint: `${s.messages.length} 条`,
        icon: 'session' as const,
        run: () => {
          onSelectSession(s.id);
          onSwitchTab('ask');
          onClose();
        },
      })),
    ];

    const lower = q.toLowerCase();
    const filtered = q
      ? base.filter(
          (item) =>
            item.label.toLowerCase().includes(lower) ||
            item.group.toLowerCase().includes(lower)
        )
      : base;

    return [...list, ...filtered];
  }, [query, sessions, onClose, onNewSession, onQuickQuery, onSelectSession, onSwitchTab]);

  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIdx((i) => (items.length ? (i + 1) % items.length : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIdx((i) => (items.length ? (i - 1 + items.length) % items.length : 0));
      } else if (e.key === 'Enter' && items[activeIdx]) {
        e.preventDefault();
        items[activeIdx].run();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, items, activeIdx, onClose]);

  if (!open) return null;

  const renderIcon = (icon: CommandItem['icon']) => {
    switch (icon) {
      case 'ask':
      case 'query':
        return <Sparkles size={14} className="text-sky-400" />;
      case 'stats':
        return <BarChart3 size={14} className="text-indigo-400" />;
      case 'monitor':
        return <Radar size={14} className="text-emerald-400" />;
      case 'new':
        return <Plus size={14} className="text-sky-300" />;
      default:
        return <MessageSquare size={14} className="text-slate-400" />;
    }
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center pt-[14vh] px-4">
      <div className="fixed inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div
        role="dialog"
        aria-modal="true"
        className="relative z-10 w-[560px] max-w-full rounded-2xl bg-[#0b0f19]/95 backdrop-blur-xl border border-white/[0.12] shadow-2xl overflow-hidden animate-modal-in"
      >
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-white/[0.08]">
          <Search size={16} className="text-slate-400 flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="输入命令、CVE 编号或搜索会话…"
            className="flex-1 bg-transparent text-sm text-white placeholder:text-slate-500 focus:outline-none"
          />
          <kbd className="px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/[0.1] text-[10px] font-mono text-slate-400">
            ESC
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2 space-y-0.5">
          {items.length === 0 ? (
            <p className="py-8 text-center text-xs text-slate-500">无匹配命令</p>
          ) : (
            items.map((item, idx) => {
              const selected = idx === activeIdx;
              return (
                <button
                  key={item.id}
                  onMouseEnter={() => setActiveIdx(idx)}
                  onClick={item.run}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors ${
                    selected
                      ? 'bg-white/[0.09] text-white'
                      : 'text-slate-300 hover:bg-white/[0.04]'
                  }`}
                >
                  <span className="flex-shrink-0">{renderIcon(item.icon)}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate">{item.label}</p>
                    <p className="text-[10px] text-slate-500">{item.group}</p>
                  </div>
                  {item.hint && (
                    <span className="text-[10px] font-mono text-slate-400 flex-shrink-0">
                      {item.hint}
                    </span>
                  )}
                  {selected && <CornerDownLeft size={12} className="text-sky-400 flex-shrink-0" />}
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

import { MessageSquare, Plus, Trash2, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import type { Session } from '../utils/storage';

interface Props {
  sessions: Session[];
  currentId: string | null;
  collapsed: boolean;
  onToggle: () => void;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onDelete: (id: string) => void;
}

// 会话侧边栏（可收起）：折叠态为窄图标条，展开态为完整面板（AskTab 控制宽度过渡）。
export default function SessionList({
  sessions, currentId, collapsed, onToggle, onSelect, onCreate, onDelete,
}: Props) {
  // 折叠态：窄条，只留展开 / 新建两个按钮
  if (collapsed) {
    return (
      <div className="flex flex-col items-center h-full soc-glass py-4 gap-3">
        <button
          onClick={onToggle}
          aria-label="展开会话列表"
          title="展开会话列表"
          className="p-2 text-soc-text-muted hover:text-soc-primary hover:bg-soc-hover transition-colors"
        >
          <PanelLeftOpen size={16} />
        </button>
        <button
          onClick={onCreate}
          aria-label="新建对话"
          title="新建对话"
          className="p-2 text-soc-text-muted hover:text-soc-primary hover:bg-soc-hover transition-colors"
        >
          <Plus size={16} />
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full soc-glass">
      <div className="p-5 border-b border-soc-border/70">
        <div className="flex items-center justify-between mb-4">
          <div className="soc-eyebrow">Sessions · 会话</div>
          <button
            onClick={onToggle}
            aria-label="收起会话列表"
            title="收起会话列表"
            className="p-1.5 text-soc-text-muted hover:text-soc-primary hover:bg-soc-hover transition-colors"
          >
            <PanelLeftClose size={15} />
          </button>
        </div>
        <button
          onClick={onCreate}
          className="soc-btn-ghost w-full flex items-center justify-center gap-2 px-4 py-2.5 text-sm tracking-[0.12em]"
        >
          <Plus size={15} />
          新建对话
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {sessions.length === 0 ? (
          <div className="p-4 text-center text-soc-text-muted text-sm">暂无会话历史</div>
        ) : (
          sessions.map((session, idx) => (
            <div
              key={session.id}
              onClick={() => onSelect(session.id)}
              className={`soc-edge group relative px-5 py-3.5 border-b border-soc-border/50 cursor-pointer transition-colors ${
                currentId === session.id
                  ? 'bg-soc-hover soc-edge-active'
                  : 'hover:bg-soc-hover'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 mb-1.5">
                    <span className="font-mono text-[10px] text-soc-text-muted">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                    <MessageSquare
                      size={13}
                      className={`flex-shrink-0 ${
                        currentId === session.id ? 'text-soc-primary' : 'text-soc-text-muted'
                      }`}
                    />
                    <p
                      className={`text-sm truncate ${
                        currentId === session.id ? 'text-soc-text-primary' : 'text-soc-text-secondary'
                      }`}
                    >
                      {session.title}
                    </p>
                  </div>
                  <p className="text-[11px] text-soc-text-muted font-mono pl-7">
                    {session.messages.length} MSG · {new Date(session.createdAt).toLocaleDateString()}
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(session.id);
                  }}
                  aria-label={`删除会话 ${session.title}`}
                  className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100 p-1 text-soc-text-muted hover:text-soc-danger transition-all"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

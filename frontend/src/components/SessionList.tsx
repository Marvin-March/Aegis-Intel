import { MessageSquare, Plus, Trash2, PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import type { Session } from '../utils/storage';
import { Button } from './ui/Button';

interface Props {
  sessions: Session[];
  currentId: string | null;
  collapsed: boolean;
  onToggle: () => void;
  onSelect: (id: string) => void;
  onCreate: () => void;
  onDelete: (id: string) => void;
}

export default function SessionList({
  sessions,
  currentId,
  collapsed,
  onToggle,
  onSelect,
  onCreate,
  onDelete,
}: Props) {
  if (collapsed) {
    return (
      <div className="flex flex-col items-center h-full aegis-surface py-2.5 gap-2">
        <button
          onClick={onToggle}
          aria-label="展开会话列表"
          title="展开会话列表"
          className="w-8 h-8 flex items-center justify-center rounded text-soc-text-muted hover:text-soc-text-primary hover:bg-soc-hover transition-colors"
        >
          <PanelLeftOpen size={15} />
        </button>
        <button
          onClick={onCreate}
          aria-label="新建对话"
          title="新建对话"
          className="w-8 h-8 flex items-center justify-center rounded text-soc-primary hover:bg-soc-primary/10 transition-colors"
        >
          <Plus size={15} />
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full aegis-surface overflow-hidden">
      <div className="px-3 py-2.5 border-b border-soc-border space-y-2.5">
        <div className="flex items-center justify-between">
          <span className="aegis-section-label">Sessions · {sessions.length}</span>
          <button
            onClick={onToggle}
            aria-label="收起会话列表"
            title="收起会话列表"
            className="p-1 rounded text-soc-text-muted hover:text-soc-text-primary hover:bg-soc-hover transition-colors"
          >
            <PanelLeftClose size={14} />
          </button>
        </div>
        <Button variant="secondary" size="sm" onClick={onCreate} className="w-full">
          <Plus size={14} className="text-soc-primary" />
          新建研判会话
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-1.5 space-y-0.5">
        {sessions.length === 0 ? (
          <div className="p-4 text-center text-soc-text-muted text-xs">暂无会话历史</div>
        ) : (
          sessions.map((session) => {
            const active = currentId === session.id;
            return (
              <div
                key={session.id}
                onClick={() => onSelect(session.id)}
                className={`group relative flex items-start justify-between gap-2 px-2.5 py-2 rounded cursor-pointer transition-colors ${
                  active
                    ? 'bg-soc-elevated border border-soc-border-default'
                    : 'border border-transparent hover:bg-soc-hover/70'
                }`}
              >
                {active && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-[2px] rounded-r bg-soc-primary" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5 mb-0.5">
                    <MessageSquare
                      size={12}
                      className={`flex-shrink-0 ${
                        active ? 'text-soc-primary' : 'text-soc-text-muted'
                      }`}
                    />
                    <p
                      className={`text-xs truncate ${
                        active ? 'text-soc-text-primary font-medium' : 'text-soc-text-secondary'
                      }`}
                    >
                      {session.title}
                    </p>
                  </div>
                  <p className="text-[10px] text-soc-text-muted font-mono tabular-nums pl-4">
                    {session.messages.length} msg · {new Date(session.createdAt).toLocaleDateString()}
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onDelete(session.id);
                  }}
                  aria-label={`删除会话 ${session.title}`}
                  className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100 p-1 rounded text-soc-text-muted hover:text-red-400 hover:bg-red-500/10 transition-colors"
                >
                  <Trash2 size={13} />
                </button>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

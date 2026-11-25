import { Play, MessageSquare } from 'lucide-react';
import { Button } from './ui/Button';

interface Props {
  demo: boolean;
  onEnterDemo: () => void;
  sessionTitle?: string;
  messageCount?: number;
}

export default function AskHero({ demo, onEnterDemo, sessionTitle, messageCount = 0 }: Props) {
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-2 border-b border-soc-border bg-soc-panel/80 flex-shrink-0">
      <div className="flex items-center gap-2 min-w-0">
        <MessageSquare size={13} className="text-soc-primary flex-shrink-0" />
        <span className="text-xs font-medium text-soc-text-primary truncate">
          {sessionTitle || '新对话'}
        </span>
        {messageCount > 0 && (
          <span className="px-1.5 py-0.5 rounded bg-soc-elevated border border-soc-border text-[10px] font-mono text-soc-text-muted tabular-nums flex-shrink-0">
            {messageCount} 条记录
          </span>
        )}
      </div>

      {!demo && (
        <Button variant="secondary" size="xs" onClick={onEnterDemo}>
          <Play size={11} className="text-soc-primary" />
          演示模式
        </Button>
      )}
    </div>
  );
}

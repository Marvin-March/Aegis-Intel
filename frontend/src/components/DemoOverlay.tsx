import { useEffect } from 'react';
import { Play, X, Clapperboard } from 'lucide-react';
import { DEMO_SCENES } from '../hooks/useDemoPlayer';
import { Button } from './ui/Button';

interface Props {
  current: number;
  playing: boolean;
  onPlayScene: (index: number) => void;
  onPlayAll: () => void;
  onExit: () => void;
}

export default function DemoOverlay({ current, playing, onPlayScene, onPlayAll, onExit }: Props) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onExit();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onExit]);

  return (
    <div className="aegis-surface px-3.5 py-2.5 flex items-center gap-3 flex-wrap flex-shrink-0">
      <div className="flex items-center gap-2">
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-soc-primary/15 border border-soc-primary/35 text-[10px] font-mono text-soc-primary">
          <Clapperboard size={11} />
          DEMO
        </span>
        <span className="text-xs font-mono text-soc-text-primary tabular-nums">
          {current >= 0
            ? `${current + 1}/${DEMO_SCENES.length} · ${DEMO_SCENES[current].name}`
            : '就绪'}
        </span>
      </div>

      <div className="flex items-center gap-1.5">
        {DEMO_SCENES.map((s, i) => (
          <span
            key={s.name}
            title={s.name}
            className={`w-4 h-1 rounded-full transition-colors ${
              i < current
                ? 'bg-soc-primary'
                : i === current
                  ? 'bg-soc-primary/80'
                  : 'bg-soc-border-default'
            }`}
          />
        ))}
      </div>

      <div className="flex items-center gap-1.5 ml-auto flex-wrap">
        <Button variant="primary" size="xs" onClick={onPlayAll} disabled={playing}>
          <Play size={11} />
          一键连播
        </Button>
        {DEMO_SCENES.map((s, i) => (
          <Button
            key={s.name}
            variant="secondary"
            size="xs"
            onClick={() => onPlayScene(i)}
            disabled={playing}
          >
            {s.name}
          </Button>
        ))}
        <Button variant="danger" size="xs" onClick={onExit}>
          <X size={11} />
          退出 (Esc)
        </Button>
      </div>
    </div>
  );
}

import { useEffect } from 'react';
import { Play, X, Clapperboard } from 'lucide-react';
import { DEMO_SCENES } from '../hooks/useDemoPlayer';

interface Props {
  current: number; // -1 = 尚未开始
  playing: boolean;
  onPlayScene: (index: number) => void;
  onPlayAll: () => void;
  onExit: () => void;
}

// 演示模式覆盖层：顶部水印（fixed）+ 底部演示控制条（随文档流，不遮挡输入区）
export default function DemoOverlay({ current, playing, onPlayScene, onPlayAll, onExit }: Props) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onExit();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onExit]);

  return (
    <>
      {/* 半透明水印（缓闪），不遮挡内容 */}
      <div className="pointer-events-none fixed top-2.5 left-1/2 -translate-x-1/2 z-40 px-4 py-1 border border-soc-primary/30 bg-soc-bg/60 backdrop-blur-sm text-[11px] text-soc-primary/80 tracking-[0.42em] animate-watermark">
        演示模式 · 情报问答
      </div>

      {/* 演示控制条 */}
      <div className="bg-soc-panel border border-soc-border px-4 py-3 flex items-center gap-4 flex-wrap animate-panel-reveal">
        <span className="flex items-center gap-1.5 text-[11px] text-soc-text-muted tracking-[0.2em] flex-shrink-0">
          <Clapperboard size={13} className="text-soc-primary" />
          DEMO
        </span>

        <span className="text-sm text-soc-text-primary font-mono">
          {current >= 0
            ? `第 ${current + 1}/${DEMO_SCENES.length} 幕 · ${DEMO_SCENES[current].name}`
            : '就绪'}
        </span>

        {/* 进度菱形 */}
        <div className="flex items-center gap-2">
          {DEMO_SCENES.map((s, i) => (
            <span
              key={s.name}
              title={s.name}
              className={`w-1.5 h-1.5 rotate-45 transition-all duration-300 ${
                i < current
                  ? 'bg-soc-primary'
                  : i === current && playing
                    ? 'bg-soc-primary animate-pulse scale-125'
                    : i === current
                      ? 'bg-soc-primary/60'
                      : 'bg-soc-border'
              }`}
            />
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto flex-wrap">
          <button
            onClick={onPlayAll}
            disabled={playing}
            className="soc-btn-primary px-3 py-1.5 text-xs font-medium tracking-[0.12em] disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            <Play size={12} />
            一键连播
          </button>
          {DEMO_SCENES.map((s, i) => (
            <button
              key={s.name}
              onClick={() => onPlayScene(i)}
              disabled={playing}
              className="soc-btn-ghost px-3 py-1.5 text-xs tracking-[0.12em] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {s.name}
            </button>
          ))}
          <button
            onClick={onExit}
            className="px-3 py-1.5 border border-soc-danger/50 text-soc-danger hover:bg-soc-danger/10 text-xs tracking-[0.12em] transition-colors flex items-center gap-1.5"
          >
            <X size={12} />
            退出演示 (Esc)
          </button>
        </div>
      </div>
    </>
  );
}

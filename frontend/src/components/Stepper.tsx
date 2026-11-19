import { useEffect, useState } from 'react';
import { Check } from 'lucide-react';

interface Step {
  label: string;
  detail: string;
  timing?: number;
}

interface Props {
  steps: Step[];
  activeIndex: number;
  /** 每步点亮间隔；演示模式 1000ms，普通 600ms */
  stepMs?: number;
  /** false = 历史消息整段直出，不重放逐级点亮（K1） */
  animate?: boolean;
}

export default function Stepper({ steps, activeIndex, stepMs = 600, animate = true }: Props) {
  const [visibleIndex, setVisibleIndex] = useState(animate ? -1 : activeIndex);

  useEffect(() => {
    if (!animate) {
      setVisibleIndex(activeIndex);
      return;
    }
    if (visibleIndex >= activeIndex) return;
    const timer = setTimeout(() => {
      setVisibleIndex((v) => Math.min(v + 1, activeIndex));
    }, stepMs);
    return () => clearTimeout(timer);
  }, [animate, activeIndex, visibleIndex, stepMs]);

  return (
    <div className="flex items-center gap-0 flex-wrap">
      {steps.map((step, idx) => {
        const lit = idx <= visibleIndex;
        const isCurrent = animate && idx === visibleIndex && visibleIndex < activeIndex;
        return (
          <div key={idx} className="flex items-center">
            <div
              className={`flex items-center gap-2.5 px-3 py-2 border transition-all duration-500 ${
                lit
                  ? 'bg-soc-hover border-soc-primary/45'
                  : 'bg-soc-panel border-soc-border'
              } ${isCurrent ? 'animate-step-breathe' : ''}`}
            >
              {/* 序号/勾选：跳过时勾弹入 */}
              <div
                className={`w-5 h-5 flex items-center justify-center text-[10px] font-mono border transition-all duration-300 ${
                  lit
                    ? 'border-soc-primary text-soc-primary bg-soc-primary/10'
                    : 'border-soc-border text-soc-text-muted'
                }`}
              >
                {idx < visibleIndex ? (
                  <Check size={11} className="animate-fade-slide-in" />
                ) : (
                  String(idx + 1).padStart(2, '0')
                )}
              </div>
              <div className="min-w-0">
                <p
                  className={`text-xs tracking-[0.12em] ${
                    lit ? 'text-soc-primary' : 'text-soc-text-muted'
                  }`}
                >
                  {step.label}
                </p>
                {lit && (
                  <p className="text-[11px] text-soc-text-secondary truncate max-w-[220px] animate-fade-slide-in">
                    {step.detail}
                  </p>
                )}
              </div>
              {step.timing !== undefined && lit && (
                <span className="ml-1.5 px-1.5 py-0.5 border border-soc-border text-soc-text-muted text-[10px] font-mono animate-fade-slide-in">
                  {step.timing}ms
                </span>
              )}
            </div>
            {idx < steps.length - 1 && (
              <div className={`h-px w-7 transition-all duration-500 ${idx < visibleIndex ? 'bg-soc-primary/60' : 'bg-soc-border'}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

import { useEffect, useState } from 'react';
import { Check, ChevronRight } from 'lucide-react';

interface Step {
  label: string;
  detail: string;
  timing?: number;
}

interface Props {
  steps: Step[];
  activeIndex: number;
  stepMs?: number;
  animate?: boolean;
}

export default function Stepper({ steps, activeIndex, stepMs = 450, animate = true }: Props) {
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
    <div className="flex items-center gap-1.5 flex-wrap">
      {steps.map((step, idx) => {
        const lit = idx <= visibleIndex;
        return (
          <div key={idx} className="flex items-center gap-1.5">
            <div
              className={`inline-flex items-center gap-1.5 px-2 py-1 rounded border text-[11px] transition-colors ${
                lit
                  ? 'bg-soc-panel border-soc-border-default text-soc-text-primary'
                  : 'bg-soc-bg/50 border-soc-border text-soc-text-muted'
              }`}
            >
              <span
                className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-[9px] font-mono ${
                  lit
                    ? 'bg-soc-primary/15 text-soc-primary'
                    : 'bg-soc-elevated text-soc-text-muted'
                }`}
              >
                {idx < visibleIndex ? <Check size={9} /> : idx + 1}
              </span>
              <span className="font-medium">{step.label}</span>
              {lit && step.detail && (
                <span className="font-mono text-[10px] text-soc-text-secondary truncate max-w-[180px]">
                  {step.detail}
                </span>
              )}
              {step.timing !== undefined && lit && (
                <span className="font-mono text-[10px] text-soc-text-muted tabular-nums">
                  {step.timing}ms
                </span>
              )}
            </div>
            {idx < steps.length - 1 && (
              <ChevronRight
                size={12}
                className={idx < visibleIndex ? 'text-soc-primary/60' : 'text-soc-border-strong'}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

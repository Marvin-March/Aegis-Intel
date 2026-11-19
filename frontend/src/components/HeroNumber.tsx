import { useEffect, useState } from 'react';
import { animateNumber } from '../utils/animation';

interface Props {
  label: string;
  value: number;
  suffix?: string;
  duration?: number;
  /** 入场错峰延迟 ms */
  delay?: number;
}

export default function HeroNumber({ label, value, suffix = '', duration = 2000, delay = 0 }: Props) {
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      animateNumber(0, value, duration, setDisplayValue);
    }, delay);
    return () => clearTimeout(timer);
  }, [value, duration, delay]);

  return (
    <div
      className="group relative bg-soc-panel border border-soc-border p-6 text-center soc-lift animate-fade-slide-in"
      style={delay > 0 ? { animationDelay: `${delay}ms` } : undefined}
    >
      {/* 顶部金线：hover 时展开 */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-soc-border overflow-hidden">
        <div className="h-full bg-soc-primary w-full scale-x-0 group-hover:scale-x-100 transition-transform origin-left" />
      </div>
      <p className="text-3xl font-mono text-soc-text-primary mb-2 tracking-tight">
        {displayValue.toLocaleString()}
        <span className="text-soc-primary/80 text-xl ml-0.5">{suffix}</span>
      </p>
      <p className="text-[11px] tracking-[0.2em] text-soc-text-muted font-mono">{label}</p>
    </div>
  );
}

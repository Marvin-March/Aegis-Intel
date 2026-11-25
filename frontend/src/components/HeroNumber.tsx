import { useEffect, useState } from 'react';
import { animateNumber } from '../utils/animation';

interface Props {
  label: string;
  value: number;
  suffix?: string;
  duration?: number;
  delay?: number;
  accent?: 'default' | 'cyan' | 'danger' | 'success';
}

const accentText: Record<NonNullable<Props['accent']>, string> = {
  default: 'text-soc-text-primary',
  cyan: 'text-soc-primary',
  danger: 'text-red-400',
  success: 'text-emerald-400',
};

export default function HeroNumber({
  label,
  value,
  suffix = '',
  duration = 650,
  delay = 0,
  accent = 'default',
}: Props) {
  const [displayValue, setDisplayValue] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => {
      animateNumber(0, value, duration, setDisplayValue);
    }, delay);
    return () => clearTimeout(timer);
  }, [value, duration, delay]);

  return (
    <div className="aegis-surface px-3.5 py-3 hover:border-soc-border-default transition-colors">
      <p className="text-[11px] text-soc-text-muted truncate">{label}</p>
      <p
        className={`mt-1 text-xl font-mono font-semibold tracking-tight tabular-nums ${accentText[accent]}`}
      >
        {displayValue.toLocaleString()}
        {suffix && <span className="text-xs font-normal text-soc-text-muted ml-0.5">{suffix}</span>}
      </p>
    </div>
  );
}

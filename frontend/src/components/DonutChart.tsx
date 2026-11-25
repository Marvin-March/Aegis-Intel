interface Props {
  data: Array<{ label: string; value: number; color: string }>;
}

/**
 * 精密 SVG 环形分布图（替代锯齿感较强的 CSS conic-gradient）
 */
export default function DonutChart({ data }: Props) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const safeTotal = total || 1;
  const radius = 54;
  const circumference = 2 * Math.PI * radius;

  let offsetAcc = 0;
  const slices = data.map((item) => {
    const percent = (item.value / safeTotal) * 100;
    const dashLen = (item.value / safeTotal) * circumference;
    const gap = data.length > 1 ? 3 : 0;
    const strokeDasharray = `${Math.max(dashLen - gap, 0)} ${circumference}`;
    const strokeDashoffset = -offsetAcc;
    offsetAcc += dashLen;
    return { ...item, percent, strokeDasharray, strokeDashoffset };
  });

  return (
    <div className="flex flex-col sm:flex-row items-center gap-6">
      <div className="relative w-36 h-36 flex-shrink-0">
        <svg viewBox="0 0 132 132" className="w-full h-full -rotate-90">
          <circle
            cx="66"
            cy="66"
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth="12"
          />
          {total > 0 &&
            slices.map((slice) => (
              <circle
                key={slice.label}
                cx="66"
                cy="66"
                r={radius}
                fill="none"
                stroke={slice.color}
                strokeWidth="12"
                strokeLinecap="round"
                strokeDasharray={slice.strokeDasharray}
                strokeDashoffset={slice.strokeDashoffset}
              />
            ))}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <p className="text-lg font-mono font-semibold text-soc-text-primary tabular-nums leading-none">
            {total.toLocaleString()}
          </p>
          <p className="text-[9px] font-mono tracking-widest text-soc-text-muted mt-1">
            VECTORS
          </p>
        </div>
      </div>

      <div className="flex-1 w-full space-y-2">
        {slices.map((slice) => (
          <div
            key={slice.label}
            className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg bg-white/[0.025] border border-soc-border hover:border-soc-border-default transition-colors"
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{
                  backgroundColor: slice.color,
                  boxShadow: `0 0 8px ${slice.color}66`,
                }}
              />
              <span className="text-xs text-soc-text-secondary truncate">{slice.label}</span>
            </div>
            <div className="flex items-center gap-2.5 font-mono text-xs tabular-nums flex-shrink-0">
              <span className="text-soc-text-primary font-medium">
                {slice.value.toLocaleString()}
              </span>
              <span className="text-[11px] text-soc-text-muted w-11 text-right">
                {slice.percent.toFixed(1)}%
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

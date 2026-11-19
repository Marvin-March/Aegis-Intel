interface Props {
  data: Array<{ label: string; value: number; color: string }>;
}

export default function DonutChart({ data }: Props) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  let cumulativePercent = 0;

  const slices = data.map((item) => {
    const percent = (item.value / total) * 100;
    const startAngle = (cumulativePercent * 360) / 100;
    const endAngle = ((cumulativePercent + percent) * 360) / 100;
    cumulativePercent += percent;
    return { ...item, percent, startAngle, endAngle };
  });

  const gradientStops = slices
    .map((s) => `${s.color} ${s.startAngle}deg ${s.endAngle}deg`)
    .join(', ');

  return (
    <div className="flex items-center gap-10">
      {/* 环形图：入场旋转展开 + hover 缓转 */}
      <div className="relative w-48 h-48 flex-shrink-0 animate-donut-in">
        <div
          className="w-full h-full rounded-full transition-transform duration-700 hover:rotate-[8deg]"
          style={{ background: `conic-gradient(${gradientStops})` }}
        />
        {/* 内圈挖空 */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-[130px] h-[130px] rounded-full bg-soc-panel border border-soc-border" />
        </div>
        {/* 四角刻度（方舟味） */}
        <div className="absolute inset-[-6px] pointer-events-none">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-px h-2.5 bg-soc-text-muted/50" />
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-px h-2.5 bg-soc-text-muted/50" />
          <div className="absolute left-0 top-1/2 -translate-y-1/2 h-px w-2.5 bg-soc-text-muted/50" />
          <div className="absolute right-0 top-1/2 -translate-y-1/2 h-px w-2.5 bg-soc-text-muted/50" />
        </div>
        {/* 中心总数（数字滚动） */}
        <div className="absolute inset-0 flex items-center justify-center flex-col pointer-events-none">
          <p className="text-2xl font-mono text-soc-text-primary animate-value-glow">
            {total.toLocaleString()}
          </p>
          <p className="text-[10px] font-mono tracking-[0.24em] text-soc-text-muted mt-1">
            VECTORS
          </p>
        </div>
      </div>

      {/* 图例 */}
      <div className="flex-1 grid grid-cols-2 gap-4">
        {slices.map((slice, i) => (
          <div
            key={slice.label}
            className="soc-edge flex items-center gap-3 pl-3 py-1.5 animate-fade-slide-in"
            style={{ animationDelay: `${150 + i * 90}ms` }}
          >
            <div className="w-2.5 h-2.5 rotate-45 flex-shrink-0" style={{ backgroundColor: slice.color }} />
            <div className="min-w-0">
              <p className="text-sm text-soc-text-primary font-mono">{slice.value.toLocaleString()}</p>
              <p className="text-[11px] text-soc-text-muted truncate">
                {slice.label} · {slice.percent.toFixed(1)}%
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

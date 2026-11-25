/**
 * 定制品牌与双色渐变导航 SVG 图标（Aegis Intel 视觉识别）
 */
export function AegisLogo({ className = 'w-5 h-5' }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="aegisBrandGrad" x1="4" y1="3" x2="28" y2="29" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#7dd3fc" />
          <stop offset="55%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#818cf8" />
        </linearGradient>
      </defs>
      <path
        d="M16 3.5L26.5 8.2V15.8C26.5 22.1 22.1 26.8 16 28.8C9.9 26.8 5.5 22.1 5.5 15.8V8.2L16 3.5Z"
        fill="url(#aegisBrandGrad)"
        fillOpacity="0.16"
        stroke="url(#aegisBrandGrad)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M16 8.5L21.5 16L16 23.5L10.5 16L16 8.5Z"
        fill="url(#aegisBrandGrad)"
        fillOpacity="0.28"
        stroke="#bae6fd"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
      <circle cx="16" cy="16" r="2.2" fill="#e0f2fe" />
    </svg>
  );
}

export function NavAskIcon({ active }: { active?: boolean }) {
  return (
    <span
      className={`w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0 border transition-colors ${
        active
          ? 'bg-gradient-to-br from-sky-400/20 to-indigo-500/20 border-sky-400/35'
          : 'bg-white/[0.04] border-white/[0.08] group-hover:border-sky-400/30'
      }`}
    >
      <svg viewBox="0 0 20 20" className="w-3.5 h-3.5" fill="none">
        <path
          d="M10 2.5L11.9 7.8L17.2 9.7L11.9 11.6L10 16.9L8.1 11.6L2.8 9.7L8.1 7.8L10 2.5Z"
          fill="#38bdf8"
          fillOpacity="0.3"
          stroke="#7dd3fc"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
        <circle cx="15.5" cy="4.5" r="1.2" fill="#a5b4fc" />
      </svg>
    </span>
  );
}

export function NavStatsIcon({ active }: { active?: boolean }) {
  return (
    <span
      className={`w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0 border transition-colors ${
        active
          ? 'bg-gradient-to-br from-sky-400/20 to-emerald-500/20 border-sky-400/35'
          : 'bg-white/[0.04] border-white/[0.08] group-hover:border-sky-400/30'
      }`}
    >
      <svg viewBox="0 0 20 20" className="w-3.5 h-3.5" fill="none">
        <rect x="3.5" y="10.5" width="3" height="6" rx="1" fill="#38bdf8" fillOpacity="0.6" />
        <rect x="8.5" y="6.5" width="3" height="10" rx="1" fill="#818cf8" fillOpacity="0.8" />
        <rect x="13.5" y="3.5" width="3" height="13" rx="1" fill="#34d399" fillOpacity="0.85" />
      </svg>
    </span>
  );
}

export function NavMonitorIcon({ active }: { active?: boolean }) {
  return (
    <span
      className={`w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0 border transition-colors ${
        active
          ? 'bg-gradient-to-br from-sky-400/20 to-indigo-500/20 border-sky-400/35'
          : 'bg-white/[0.04] border-white/[0.08] group-hover:border-sky-400/30'
      }`}
    >
      <svg viewBox="0 0 20 20" className="w-3.5 h-3.5" fill="none">
        <circle cx="10" cy="10" r="6.8" stroke="#64748b" strokeWidth="1.2" strokeDasharray="2.5 2" />
        <circle cx="10" cy="10" r="3.6" stroke="#38bdf8" strokeWidth="1.2" strokeOpacity="0.8" />
        <path d="M10 10L14.8 5.2" stroke="#7dd3fc" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="10" cy="10" r="1.4" fill="#38bdf8" />
      </svg>
    </span>
  );
}

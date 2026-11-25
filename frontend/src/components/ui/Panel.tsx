import type { ReactNode } from 'react';

interface PanelProps {
  title?: string;
  code?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}

/**
 * 统一面板容器（Linear / Grafana 风格：纯色深灰表面 + 1px 细边框 + 紧凑表头）
 */
export function Panel({
  title,
  code,
  subtitle,
  action,
  children,
  className = '',
  bodyClassName = 'p-4',
}: PanelProps) {
  return (
    <section className={`aegis-surface shadow-panel-sm ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-soc-border">
          <div className="flex items-center gap-2 min-w-0">
            {code && (
              <span className="text-[10px] font-mono uppercase tracking-wider text-soc-primary/80">
                {code}
              </span>
            )}
            {code && title && <span className="text-soc-border-strong">/</span>}
            {title && (
              <h2 className="text-xs font-semibold text-soc-text-primary truncate">{title}</h2>
            )}
            {subtitle && (
              <span className="hidden sm:inline text-[11px] text-soc-text-muted truncate">
                {subtitle}
              </span>
            )}
          </div>
          {action && <div className="flex items-center gap-2 flex-shrink-0">{action}</div>}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

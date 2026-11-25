import type { ButtonHTMLAttributes, ReactNode } from 'react';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
type Size = 'xs' | 'sm' | 'md';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  children: ReactNode;
}

const variantStyles: Record<Variant, string> = {
  primary:
    'bg-soc-primary text-[#051017] font-semibold border border-cyan-300/40 hover:bg-soc-primary-hover active:translate-y-px',
  secondary:
    'bg-soc-elevated text-soc-text-primary border border-soc-border-default hover:bg-soc-hover hover:border-soc-border-strong',
  ghost:
    'bg-transparent text-soc-text-secondary border border-transparent hover:bg-soc-hover hover:text-soc-text-primary',
  danger:
    'bg-red-500/10 text-red-400 border border-red-500/35 hover:bg-red-500/20 hover:border-red-500/60',
};

const sizeStyles: Record<Size, string> = {
  xs: 'h-7 px-2.5 text-[11px] gap-1.5',
  sm: 'h-8 px-3 text-xs gap-1.5',
  md: 'h-9 px-4 text-xs gap-2',
};

export function Button({
  variant = 'secondary',
  size = 'sm',
  className = '',
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`inline-flex items-center justify-center rounded transition-colors disabled:opacity-45 disabled:cursor-not-allowed whitespace-nowrap ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

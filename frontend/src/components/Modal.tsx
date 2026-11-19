import type { ReactNode } from 'react';

// ============ 应用内 Modal（替代原生 confirm）============

interface Props {
  open: boolean;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
}

export default function Modal({ open, title, children, footer, onClose }: Props) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/70 animate-overlay-in" onClick={onClose} />
      <div className="relative bg-soc-panel border border-soc-border p-6 w-[440px] max-w-[90vw] animate-modal-in">
        {/* 顶部金线 */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-soc-primary via-soc-primary/50 to-transparent" />
        <h3 className="text-base tracking-[0.16em] text-soc-text-primary mb-3 flex items-center gap-2">
          <span className="w-1.5 h-1.5 rotate-45 bg-soc-primary" />
          {title}
        </h3>
        <div className="text-sm text-soc-text-secondary leading-relaxed">{children}</div>
        {footer && <div className="flex justify-end gap-2 mt-6">{footer}</div>}
      </div>
    </div>
  );
}

import { useEffect, type ReactNode } from 'react';
import { X } from 'lucide-react';

interface Props {
  open: boolean;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  onClose: () => void;
}

export default function Modal({ open, title, children, footer, onClose }: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/75 backdrop-blur-[1px]" onClick={onClose} />
      <div
        role="dialog"
        aria-modal="true"
        className="relative rounded-lg bg-soc-panel border border-soc-border-default shadow-panel-md w-[440px] max-w-full animate-modal-in overflow-hidden"
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
          <h3 className="text-sm font-semibold text-soc-text-primary">{title}</h3>
          <button
            onClick={onClose}
            aria-label="关闭弹窗"
            className="p-1 rounded text-soc-text-muted hover:text-soc-text-primary hover:bg-soc-hover transition-colors"
          >
            <X size={14} />
          </button>
        </div>
        <div className="px-4 py-4 text-xs text-soc-text-secondary leading-relaxed">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 px-4 py-3 border-t border-soc-border bg-soc-sidebar/60">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

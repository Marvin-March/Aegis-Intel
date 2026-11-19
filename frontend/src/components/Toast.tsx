import { useEffect, useState } from 'react';
import { CheckCircle2, AlertCircle } from 'lucide-react';

// ============ 应用内 Toast（替代原生 alert）============

export interface ToastItem {
  id: number;
  kind: 'success' | 'error';
  message: string;
}

type Listener = (t: ToastItem) => void;

const listeners = new Set<Listener>();
let seq = 0;

function emit(kind: ToastItem['kind'], message: string) {
  const item: ToastItem = { id: ++seq, kind, message };
  listeners.forEach((l) => l(item));
}

export const toast = {
  success: (message: string) => emit('success', message),
  error: (message: string) => emit('error', message),
};

export default function ToastContainer() {
  const [items, setItems] = useState<ToastItem[]>([]);

  useEffect(() => {
    const listener: Listener = (t) => {
      setItems((prev) => [...prev, t]);
      window.setTimeout(() => {
        setItems((prev) => prev.filter((x) => x.id !== t.id));
      }, 3800);
    };
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  return (
    <div className="fixed top-5 right-5 z-[60] space-y-2 max-w-sm">
      {items.map((t) => (
        <div
          key={t.id}
          className={`animate-toast-in relative flex items-start gap-2 px-4 py-3 border bg-soc-panel shadow-lg text-sm ${
            t.kind === 'success'
              ? 'border-soc-success/40'
              : 'border-soc-danger/40'
          }`}
        >
          {/* 左侧状态色条 */}
          <span
            className={`absolute left-0 top-0 bottom-0 w-[2px] ${
              t.kind === 'success' ? 'bg-soc-success' : 'bg-soc-danger'
            }`}
          />
          {t.kind === 'success' ? (
            <CheckCircle2 size={15} className="flex-shrink-0 mt-0.5 text-soc-success" />
          ) : (
            <AlertCircle size={15} className="flex-shrink-0 mt-0.5 text-soc-danger" />
          )}
          <span className="text-soc-text-primary leading-relaxed break-all">{t.message}</span>
        </div>
      ))}
    </div>
  );
}

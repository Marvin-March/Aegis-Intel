import { useEffect, useState } from 'react';
import { CheckCircle2, AlertCircle } from 'lucide-react';

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
    <div className="fixed top-4 right-4 z-[60] space-y-2 max-w-sm">
      {items.map((t) => (
        <div
          key={t.id}
          className={`animate-toast-in relative overflow-hidden flex items-start gap-2.5 px-3.5 py-2.5 rounded-md border bg-soc-elevated shadow-panel-md text-xs ${
            t.kind === 'success' ? 'border-emerald-500/40' : 'border-red-500/40'
          }`}
        >
          <span
            className={`absolute left-0 top-0 bottom-0 w-[3px] ${
              t.kind === 'success' ? 'bg-emerald-400' : 'bg-red-400'
            }`}
          />
          {t.kind === 'success' ? (
            <CheckCircle2 size={14} className="flex-shrink-0 mt-0.5 text-emerald-400" />
          ) : (
            <AlertCircle size={14} className="flex-shrink-0 mt-0.5 text-red-400" />
          )}
          <span className="text-soc-text-primary leading-relaxed break-all">{t.message}</span>
        </div>
      ))}
    </div>
  );
}

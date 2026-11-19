import { Play } from 'lucide-react';

interface Props {
  demo: boolean;
  onEnterDemo: () => void;
}

// 问答区顶部：仅保留演示模式入口（右上角一行小字），不再展示统计徽章——
// 删掉 VECTORS/BENCH/COST（后两项是硬编码假数据，演示时容易造成误导），
// 给问答区腾出整块垂直空间。
export default function AskHero({ demo, onEnterDemo }: Props) {
  return (
    <div className="flex items-center justify-end">
      {!demo && (
        <button
          onClick={onEnterDemo}
          className="soc-btn-ghost px-3 py-1.5 text-xs tracking-[0.14em] flex items-center gap-1.5 flex-shrink-0"
        >
          <Play size={13} />
          演示模式
        </button>
      )}
    </div>
  );
}
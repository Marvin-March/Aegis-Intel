import { useEffect, useState } from 'react';
import { typewriter, scrollToHighlight } from '../utils/animation';

interface Props {
  text: string;
  speed?: number;
  /** 动画开关：仅本轮最新消息 true（打字机）；历史消息 false → 整段直出不重播（K1） */
  animated?: boolean;
  onComplete?: () => void;
}

type Block =
  | { type: 'p'; items: string[] }
  | { type: 'ul'; items: string[] }
  | { type: 'ol'; items: string[] }
  | { type: 'h'; level: number; items: string[] }
  | { type: 'code'; items: string[] }
  | { type: 'table'; rows: string[][] };

// 行级 Markdown 解析（K6 + 2026-10-15 补标题/代码块 + 2026-10-16 补表格/无空格标题）：
// - 行首 - / • → 无序列表；行首 数字. → 有序列表
// - 行首 1-3 个 # → 标题（### → h3；空格可有可无——模型中文输出惯用 "##一、" 无空格）
// - 成对 ``` 围栏 → 代码块（打字机誊写时保留原样，渲染时才剥围栏）
// - | 开头的连续行 → 表格（|---| 分隔行剔除）
// shift-enter 语义：代码块内部（行非空即续，避免中途 ``` 错断）
function parseBlocks(text: string): Block[] {
  const blocks: Block[] = [];
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const line = raw.trim();
    // 代码块开围栏
    if (line.startsWith('```')) {
      const inner: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        inner.push(lines[i]);
        i++;
      }
      i++; // 跳过闭围栏
      blocks.push({ type: 'code', items: inner });
      continue;
    }
    // markdown 表格（2026-10-16）：| 开头的连续行收进一个块，|---|:--:| 分隔行剔除
    if (line.startsWith('|') && line.endsWith('|')) {
      const rows: string[][] = [];
      while (i < lines.length) {
        const tl = lines[i].trim();
        if (!tl.startsWith('|')) break;
        if (!/^\|[\s:|-]+\|$/.test(tl)) {          // 纯 |:- 空格 = 分隔行，跳过
          const inner = tl.slice(1, tl.endsWith('|') ? -1 : undefined);
          rows.push(inner.split('|').map((c) => c.trim()));
        }
        i++;
      }
      if (rows.length) blocks.push({ type: 'table', rows });
      continue;
    }
    if (!line) {
      i++;
      continue;
    }
    const hm = line.match(/^(#{1,3})\s*(.+)$/);
    if (hm) {
      blocks.push({ type: 'h', level: hm[1].length, items: [hm[2]] });
      i++;
      continue;
    }
    if (/^[-•]\s+/.test(line)) {
      const item = line.replace(/^[-•]\s+/, '');
      const last = blocks[blocks.length - 1];
      if (last && last.type === 'ul') last.items.push(item);
      else blocks.push({ type: 'ul', items: [item] });
    } else if (/^\d+[.、)]\s*/.test(line)) {
      const item = line.replace(/^\d+[.、)]\s*/, '');
      const last = blocks[blocks.length - 1];
      if (last && last.type === 'ol') last.items.push(item);
      else blocks.push({ type: 'ol', items: [item] });
    } else {
      blocks.push({ type: 'p', items: [line] });
    }
    i++;
  }
  return blocks;
}

// 裸 URL 自动转链接（拒答话术里的 NVD 链接可点）；导出供拒答横幅复用
export function renderTextWithUrl(segment: string, keyPrefix: string) {
  const urlParts = segment.split(/(https?:\/\/[^\s)\]）】"']+)/g);
  if (urlParts.length === 1) return segment;
  return urlParts.map((seg, ui) => {
    const key = `${keyPrefix}-u${ui}`;
    if (/^https?:\/\//.test(seg)) {
      return (
        <a
          key={key}
          href={seg}
          target="_blank"
          rel="noopener noreferrer"
          className="text-soc-primary hover:text-cyan-300 break-all"
        >
          {seg}
        </a>
      );
    }
    return <span key={key}>{seg}</span>;
  });
}

// 行内解析：[n]/[卡n] 双引用 + **加粗** + `行内代码` + 裸 URL
function renderInline(content: string, keyPrefix: string) {
  const parts = content.split(/(\[\d+\]|\[卡\d+\])/g);
  return parts.map((part, idx) => {
    const key = `${keyPrefix}-${idx}`;
    const hitMatch = part.match(/^\[(\d+)\]$/);
    const cardMatch = part.match(/^\[卡(\d+)\]$/);
    if (hitMatch) {
      const citationIndex = parseInt(hitMatch[1], 10) - 1;
      return (
        <button
          key={key}
          onClick={() => scrollToHighlight(`hit-${citationIndex}`)}
          className="inline-flex items-center justify-center w-[18px] h-[18px] mx-0.5 text-[10px] font-mono bg-soc-primary/15 text-soc-primary hover:bg-soc-primary hover:text-soc-bg border border-soc-primary/50 transition-all cursor-pointer align-middle"
        >
          {hitMatch[1]}
        </button>
      );
    }
    if (cardMatch) {
      const cardIndex = parseInt(cardMatch[1], 10) - 1;
      return (
        <button
          key={key}
          onClick={() => scrollToHighlight(`card-${cardIndex}`)}
          className="inline-flex items-center justify-center h-[18px] px-1.5 mx-0.5 text-[10px] font-mono bg-purple-500/15 text-purple-300 hover:bg-purple-500/80 hover:text-white border border-purple-500/50 transition-all cursor-pointer align-middle"
        >
          卡{cardMatch[1]}
        </button>
      );
    }
    // 非引用段：先剥 `` 行内代码，再对普通段处理 **加粗** 与 裸 URL
    const codeParts = part.split(/(`[^`]+`)/g);
    return (
      <span key={key}>
        {codeParts.map((cp, cidx) => {
          const cKey = `${key}-c${cidx}`;
          if (cp.startsWith('`') && cp.endsWith('`') && cp.length > 2) {
            return (
              <code
                key={cKey}
                className="px-1.5 py-0.5 mx-0.5 bg-soc-hover border border-soc-border font-mono text-[12px] text-soc-primary align-middle"
              >
                {cp.slice(1, -1)}
              </code>
            );
          }
          if (!cp) return null;
          const boldParts = cp.split(/(\*\*[^*]+\*\*)/g);
          if (boldParts.length === 1) {
            return <span key={cKey}>{renderTextWithUrl(cp, cKey)}</span>;
          }
          return (
            <span key={cKey}>
              {boldParts.map((bp, bidx) => {
                const bKey = `${cKey}-b${bidx}`;
                if (bp.startsWith('**') && bp.endsWith('**') && bp.length > 4) {
                  return (
                    <strong key={bKey} className="text-soc-text-primary font-semibold">
                      {renderTextWithUrl(bp.slice(2, -2), bKey)}
                    </strong>
                  );
                }
                return <span key={bKey}>{renderTextWithUrl(bp, bKey)}</span>;
              })}
            </span>
          );
        })}
      </span>
    );
  });
}

const cursor = <span className="soc-caret" />;

export default function AnswerText({ text, speed = 15, animated = true, onComplete }: Props) {
  // 历史消息首帧即全文（避免先空后全的一帧闪烁）；动画消息从空开始
  const [displayText, setDisplayText] = useState(() => (animated ? '' : text));
  // 速度在挂载时定格，避免演示中途退出导致打字机重启
  const [spd] = useState(speed);

  useEffect(() => {
    // 历史消息：整段直出、不再重播打字动画（K1 本轮最新才动画）
    if (!animated) {
      setDisplayText(text);
      return;
    }
    const cancel = typewriter(text, spd, setDisplayText, onComplete);
    return cancel;
  }, [text, spd, animated, onComplete]);

  const blocks = parseBlocks(displayText);
  const done = displayText.length >= text.length;

  return (
    <div className="text-soc-text-primary leading-relaxed space-y-2">
      {blocks.map((b, bi) => {
        const isLast = bi === blocks.length - 1;
        if (b.type === 'p') {
          return (
            <p key={bi}>
              {renderInline(b.items[0], `b${bi}`)}
              {isLast && !done && cursor}
            </p>
          );
        }
        if (b.type === 'h') {
          const level = b.level;
          return (
            <p key={bi} className="flex items-baseline gap-2">
              <span className="text-soc-primary/90 font-semibold tracking-wide">
                {level === 1 ? '#' : level === 2 ? '##' : '###'}
              </span>
              <span
                className={
                  level === 1
                    ? 'text-[15px] font-semibold text-soc-text-primary'
                    : level === 2
                    ? 'text-[14px] font-semibold text-soc-text-primary'
                    : 'text-[13px] font-semibold text-soc-text-primary/95'
                }
              >
                {renderInline(b.items[0], `h${bi}`)}
              </span>
              {isLast && !done && cursor}
            </p>
          );
        }
        if (b.type === 'table') {
          const [head, ...body] = b.rows;
          return (
            <div key={bi} className="overflow-x-auto">
              <table className="w-full text-[12.5px] border border-soc-border">
                <thead>
                  <tr className="bg-soc-hover/60">
                    {head.map((c, ci) => (
                      <th key={ci} className="border-b border-soc-border px-2.5 py-1.5 text-left font-semibold text-soc-primary/90">
                        {renderInline(c, `t${bi}h${ci}`)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {body.map((r, ri) => (
                    <tr key={ri} className="border-b border-soc-border/40 last:border-b-0">
                      {r.map((c, ci) => (
                        <td key={ci} className="px-2.5 py-1.5 align-top text-soc-text-secondary">
                          {renderInline(c, `t${bi}r${ri}c${ci}`)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
              {isLast && !done && cursor}
            </div>
          );
        }
        if (b.type === 'code') {
          return (
            <pre
              key={bi}
              className="bg-soc-bg/80 border border-soc-border p-3 overflow-x-auto text-[12.5px] leading-relaxed text-soc-text-secondary font-mono whitespace-pre"
            >
              {b.items.map((ln, li) => (
                <span key={li} className="block">
                  {ln || ' '}
                </span>
              ))}
              {isLast && !done && cursor}
            </pre>
          );
        }
        const Tag = b.type === 'ul' ? 'ul' : 'ol';
        return (
          <Tag
            key={bi}
            className={`pl-5 space-y-1 ${b.type === 'ul' ? 'list-disc' : 'list-decimal'}`}
          >
            {b.items.map((it, ii) => (
              <li key={ii}>
                {renderInline(it, `b${bi}-${ii}`)}
                {isLast && ii === b.items.length - 1 && !done && cursor}
              </li>
            ))}
          </Tag>
        );
      })}
      {blocks.length === 0 && cursor}
    </div>
  );
}

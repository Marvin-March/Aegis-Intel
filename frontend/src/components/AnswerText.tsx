import { useEffect, useState } from 'react';
import { typewriter, scrollToHighlight } from '../utils/animation';

interface Props {
  text: string;
  speed?: number;
  animated?: boolean;
  onCiteClick?: (type: 'hit' | 'card', index: number) => void;
  onComplete?: () => void;
}

type Block =
  | { type: 'p'; items: string[] }
  | { type: 'ul'; items: string[] }
  | { type: 'ol'; items: string[] }
  | { type: 'h'; level: number; items: string[] }
  | { type: 'code'; items: string[] }
  | { type: 'table'; rows: string[][] };

function parseBlocks(text: string): Block[] {
  const blocks: Block[] = [];
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const line = raw.trim();
    if (line.startsWith('```')) {
      const inner: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        inner.push(lines[i]);
        i++;
      }
      i++;
      blocks.push({ type: 'code', items: inner });
      continue;
    }
    if (line.startsWith('|') && line.endsWith('|')) {
      const rows: string[][] = [];
      while (i < lines.length) {
        const tl = lines[i].trim();
        if (!tl.startsWith('|')) break;
        if (!/^\|[\s:|-]+\|$/.test(tl)) {
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
    } else if (/^\d+[.、]\s*/.test(line)) {
      const item = line.replace(/^\d+[.、]\s*/, '');
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

export function renderTextWithUrl(segment: string, keyPrefix: string) {
  const urlParts = segment.split(/(https?:\/\/[^\s\])】"']+)/g);
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
          className="text-sky-300 hover:underline break-all"
        >
          {seg}
        </a>
      );
    }
    return <span key={key}>{seg}</span>;
  });
}

function renderInline(
  content: string,
  keyPrefix: string,
  onCiteClick?: (type: 'hit' | 'card', index: number) => void
) {
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
          type="button"
          onClick={() =>
            onCiteClick ? onCiteClick('hit', citationIndex) : scrollToHighlight(`hit-${citationIndex}`)
          }
          title={`查看检索证据 [${hitMatch[1]}]`}
          className="inline-flex items-center justify-center min-w-[19px] h-[18px] px-1 mx-0.5 rounded-md bg-sky-500/20 border border-sky-400/35 text-sky-300 hover:bg-sky-400 hover:text-slate-950 text-[10px] font-mono tabular-nums align-baseline transition-colors"
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
          type="button"
          onClick={() =>
            onCiteClick ? onCiteClick('card', cardIndex) : scrollToHighlight(`card-${cardIndex}`)
          }
          title={`查看漏洞卡片 [卡${cardMatch[1]}]`}
          className="inline-flex items-center justify-center h-[18px] px-1.5 mx-0.5 rounded-md bg-indigo-500/20 border border-indigo-400/35 text-indigo-200 hover:bg-indigo-400 hover:text-slate-950 text-[10px] font-mono tabular-nums align-baseline transition-colors"
        >
          卡{cardMatch[1]}
        </button>
      );
    }

    const codeParts = part.split(/(`[^`]+`)/g);
    return (
      <span key={key}>
        {codeParts.map((cp, cidx) => {
          const cKey = `${key}-c${cidx}`;
          if (cp.startsWith('`') && cp.endsWith('`') && cp.length > 2) {
            return (
              <code
                key={cKey}
                className="px-1.5 py-0.5 mx-0.5 rounded-md bg-white/[0.07] font-mono text-[12.5px] text-sky-300"
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
                    <strong key={bKey} className="text-white font-semibold">
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

export default function AnswerText({
  text,
  speed = 12,
  animated = true,
  onCiteClick,
  onComplete,
}: Props) {
  const [displayText, setDisplayText] = useState(() => (animated ? '' : text));
  const [spd] = useState(speed);

  useEffect(() => {
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
    <div className="text-[14.5px] text-slate-200 leading-[1.8] space-y-2.5">
      {blocks.map((b, bi) => {
        const isLast = bi === blocks.length - 1;
        if (b.type === 'p') {
          return (
            <p key={bi}>
              {renderInline(b.items[0], `b${bi}`, onCiteClick)}
              {isLast && !done && cursor}
            </p>
          );
        }
        if (b.type === 'h') {
          const cls =
            b.level === 1
              ? 'text-base font-semibold text-white pt-2'
              : b.level === 2
                ? 'text-[15px] font-semibold text-white pt-2'
                : 'text-[14px] font-semibold text-sky-300 pt-1.5';
          return (
            <h4 key={bi} className={cls}>
              {renderInline(b.items[0], `h${bi}`, onCiteClick)}
              {isLast && !done && cursor}
            </h4>
          );
        }
        if (b.type === 'table') {
          const [head, ...body] = b.rows;
          return (
            <div key={bi} className="overflow-x-auto rounded-xl border border-white/[0.08]">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-white/[0.03] border-b border-white/[0.08]">
                    {head.map((c, ci) => (
                      <th
                        key={ci}
                        className="px-3 py-2 text-left font-semibold text-white whitespace-nowrap"
                      >
                        {renderInline(c, `t${bi}h${ci}`, onCiteClick)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                  {body.map((r, ri) => (
                    <tr key={ri} className="hover:bg-white/[0.025]">
                      {r.map((c, ci) => (
                        <td key={ci} className="px-3 py-2 align-top text-slate-300">
                          {renderInline(c, `t${bi}r${ri}c${ci}`, onCiteClick)}
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
              className="rounded-xl bg-black/50 border border-white/[0.08] p-3.5 overflow-x-auto text-xs leading-relaxed text-sky-100 font-mono"
            >
              {b.items.map((ln, li) => (
                <span key={li} className="block">
                  {ln || ' '}
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
            className={`pl-5 space-y-1 text-slate-300 ${
              b.type === 'ul'
                ? 'list-disc marker:text-slate-500'
                : 'list-decimal marker:text-slate-500'
            }`}
          >
            {b.items.map((it, ii) => (
              <li key={ii}>
                {renderInline(it, `b${bi}-${ii}`, onCiteClick)}
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

// ============ 演示模式驱动器（T1）============
// 四幕剧本状态机：清空输入 → 打字机逐字输入(30字/秒) → 发送 → 等待整轮渲染完成
// 渲染完成回调由 AskTab 的 demoSend 提供 Promise，幕间停 3 秒

import { useRef, useState } from 'react';

export interface DemoScene {
  name: string;
  query: string;
}

export const DEMO_SCENES: DemoScene[] = [
  { name: '点查', query: 'CVE-2026-59822 是什么漏洞？有修复建议吗？' },
  { name: '语义', query: '有哪些针对 MCP 工具链的供应链攻击？' },
  { name: '关联', query: '这个漏洞有哪些分析文章？' },
  { name: '拒答', query: 'CVE-2024-3094 是什么漏洞？' },
];

const TYPE_INTERVAL_MS = 33; // 30 字/秒
const TYPE_DONE_PAUSE_MS = 600; // 打字完成后稍作停顿再发送
const SCENE_GAP_MS = 3000; // 连播幕间停顿
const SCENE_TIMEOUT_MS = 45000; // 单幕兜底超时，防止渲染回调丢失导致连播卡死

interface Options {
  setInput: (v: string) => void;
  send: (query: string) => Promise<void>;
}

export function useDemoPlayer({ setInput, send }: Options) {
  const [active, setActive] = useState(false);
  const [current, setCurrent] = useState(-1);
  const [playing, setPlaying] = useState(false);
  const runRef = useRef(0);

  const sleep = (ms: number, run: number) =>
    new Promise<boolean>((resolve) => {
      window.setTimeout(() => resolve(runRef.current === run), ms);
    });

  const playScene = async (index: number, run: number): Promise<boolean> => {
    const scene = DEMO_SCENES[index];
    setCurrent(index);
    setInput('');
    for (let i = 1; i <= scene.query.length; i++) {
      if (runRef.current !== run) return false;
      setInput(scene.query.slice(0, i));
      if (!(await sleep(TYPE_INTERVAL_MS, run))) return false;
    }
    if (!(await sleep(TYPE_DONE_PAUSE_MS, run))) return false;
    await Promise.race([send(scene.query), sleep(SCENE_TIMEOUT_MS, run)]);
    return runRef.current === run;
  };

  // play() 不带参数 = 一键连播四幕；带索引 = 单幕重放
  const play = async (index?: number) => {
    const run = ++runRef.current;
    setPlaying(true);
    if (index !== undefined) {
      const ok = await playScene(index, run);
      if (runRef.current === run && ok) {
        setInput('');
        setPlaying(false);
      }
      return;
    }
    for (let i = 0; i < DEMO_SCENES.length; i++) {
      const ok = await playScene(i, run);
      if (!ok) break;
      if (i < DEMO_SCENES.length - 1) {
        if (!(await sleep(SCENE_GAP_MS, run))) break;
      }
    }
    if (runRef.current === run) {
      setInput('');
      setPlaying(false);
    }
  };

  const enter = () => {
    setActive(true);
  };

  const exit = () => {
    runRef.current++;
    setActive(false);
    setCurrent(-1);
    setPlaying(false);
    setInput('');
  };

  return { active, current, playing, enter, exit, play };
}

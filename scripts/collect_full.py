#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_full.py —— 一键全链路采集（"立即采集"按钮的真实执行体）

链路：采集(run_daily) → 富化(enrich_daily) → 切块(preprocess) → 向量增量(build_vector)
目的（2026-10-13 定）：新采到的数据跑完本链后必须立即出现在问答结果里——
  ① run_daily  采集+清洗入库+补正文+导出（幂等判重，只收新增）
  ② enrich_daily 加工链：AI 复核 → L1 确定性富化 → L3 LLM 富化 → 清洗 → 导出 → 体检
                （全幂等：字段空值=待处理，只处理新增的几十条，几分钟）
  ③ preprocess_corpus 幂等重生成 chunks.jsonl（id=sha1(record_id#块序号)，老块逐字节不变）
  ④ build_vector_wemm 断点续传：跳过已入库 54,297 块，只嵌入新块（本机 CPU 分钟级）

设计：前端不变——/api/collect 拉起本脚本替代直接跑 run_daily；
     每步失败不阻塞后续（日志留痕，checkpoint 次日自动补）；
     .collect_full.lock 携带 phase（采集/富化/切块/向量），/api/runs 据此展示运行中状态。
"""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
MODEL = ROOT.parent / "models" / "WeMM-Embedding-4B"   # 查询侧同款模型（闸门已认证一致性）

LOCK = ROOT / "data" / ".collect_full.lock"

STEPS = [
    ("采集", ["scripts/run_daily.py", "--mode", "manual"]),
    ("富化", ["scripts/enrich_daily.py"]),
    ("切块", ["scripts/preprocess_corpus.py"]),
    ("向量", ["scripts/build_vector_wemm.py", "--model", str(MODEL)]),
]


def _lock(phase: str):
    LOCK.write_text(f"pid={os.getpid()} phase={phase} at "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S')}", encoding="utf-8")


def _pid_alive(pid: int) -> bool:
    """进程存活探测（探测失败按存活处理，宁可不误杀）。
    2026-10-16 修：tasklist 对不存在的 PID 也返回 0，返回码判存活恒 True——
    强杀残留的死锁会让下次运行误判"已有全链在执行"而拒绝启动。改看 CSV 输出行。"""
    try:
        if sys.platform == "win32":
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                               capture_output=True, timeout=10,
                               encoding="gbk", errors="ignore")
            return f'"{pid}"' in (r.stdout or "")
        os.kill(pid, 0)
        return True
    except Exception:
        return True


def run(name: str, cmd: list, hours: int = 3):
    _lock(name)
    print(f"\n===== 阶段 {name} =====  {' '.join(cmd)}", flush=True)
    t0 = time.time()
    try:
        r = subprocess.run([PY, "-u"] + cmd, cwd=str(ROOT), timeout=hours * 3600)
        print(f"[{name}] 完成 exit={r.returncode} 耗时 {round((time.time() - t0) / 60, 1)} 分钟", flush=True)
    except subprocess.TimeoutExpired:
        print(f"[{name}] 超时（>{hours}h），跳过，checkpoint 下次续", flush=True)
    except Exception as e:
        print(f"[{name}] 异常 {type(e).__name__}: {e}，继续下一步（checkpoint 兜底）", flush=True)


def main():
    ap = argparse.ArgumentParser(description="一键全链路采集（可指定起始阶段）")
    ap.add_argument("--start", default="采集", choices=[s[0] for s in STEPS],
                    help="从哪个阶段开始（默认采集）")
    ap.add_argument("--enrich-only", default="",
                    help="富化阶段只跑指定步骤（传给 enrich_daily --only，逗号分隔）")
    args = ap.parse_args()

    LOCK.parent.mkdir(parents=True, exist_ok=True)
    # 防撞锁：定时 06:05 与手动触发、上一天未跑完的链之间不打架
    if LOCK.exists():
        m = re.search(r"pid=(\d+)", LOCK.read_text(encoding="utf-8"))
        if m and _pid_alive(int(m.group(1))):
            print(f"[collect_full] 已有全链在执行（{LOCK.read_text(encoding='utf-8').strip()}），"
                  f"本次退出", flush=True)
            return
        print("[collect_full] 发现陈旧锁，自动清理后继续", flush=True)
        LOCK.unlink(missing_ok=True)
    start_i = next(i for i, (n, _) in enumerate(STEPS) if n == args.start)
    _lock(args.start)
    try:
        for name, cmd in STEPS[start_i:]:
            if name == "富化" and args.enrich_only:
                cmd = cmd + ["--only", args.enrich_only]
            run(name, cmd)
    finally:
        LOCK.unlink(missing_ok=True)
        print("\n[collect_full] 全链结束", flush=True)


if __name__ == "__main__":
    main()

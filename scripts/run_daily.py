#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_daily.py —— 采集层统一入口（自动化 + 手动触发 + 一次性回填）

三种模式：
  daily   每日增量（默认）：四采集器并行（增量判重）→ deep_fill 补正文 → 运行报告+心跳
  manual  手动触发：与 daily 相同，报告中标记 trigger=manual（供前端“立即采集”使用）
  backfill 一次性回填（部署后跑一次）：先知全量翻页、RSS 回看 90 天、NVD 窗口放宽到 120 天、
          deep_fill 补全部空正文。跑一次即可，日常切回 daily。

通用参数：
  --only xianzhi,rss,vuln,cnnvd,deepfill   只跑指定阶段（逗号分隔）
  --out-dir ./data                          数据目录
内置一档优化：运行锁（防撞车）、四采集器并行、每阶段日志落盘、运行报告 + 心跳文件。
微信记录由 deep_fill 自动标 no_body 跳过（平台性放弃，见清单）。

用法：
    uv run python scripts/run_daily.py                       # 每日增量
    uv run python scripts/run_daily.py --mode manual         # 手动触发
    uv run python scripts/run_daily.py --mode backfill       # 部署后一次性回填
    uv run python scripts/run_daily.py --only cnnvd,report   # 只跑 CNNVD+出报告
"""

import argparse
import concurrent.futures
import io
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Windows GBK 编码兼容：强制 stdout 用 UTF-8
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

COLLECTORS = {
    "xianzhi": ["scripts/xianzhi_crawler.py"],
    "rss": ["scripts/rss_collector.py"],
    "vuln": ["scripts/vuln_collector.py", "--source", "all"],
    "cnnvd": ["scripts/cnnvd_collector.py"],
}


def run_stage(name: str, cmd: list, out_dir: Path, log_dir: Path) -> dict:
    t0 = time.time()
    log_file = log_dir / f"{name}.log"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    env["PYTHONUTF8"] = "1"
    try:
        r = subprocess.run([PY, "-u"] + cmd + ["--out-dir", str(out_dir)],
                           cwd=str(ROOT), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=7200, env=env)
        log_file.write_text(r.stdout[-20000:] + ("\n[STDERR]\n" + r.stderr[-5000:] if r.stderr else ""),
                            encoding="utf-8")
        tail = [l for l in r.stdout.strip().splitlines() if l.strip()][-3:]
        return {"stage": name, "ok": r.returncode == 0, "seconds": round(time.time() - t0, 1),
                "tail": tail, "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"stage": name, "ok": False, "seconds": round(time.time() - t0, 1),
                "tail": ["超时 7200s"], "cmd": " ".join(cmd)}
    except Exception as e:
        return {"stage": name, "ok": False, "seconds": round(time.time() - t0, 1),
                "tail": [f"{type(e).__name__}: {e}"], "cmd": " ".join(cmd)}


def db_count(out_dir: Path) -> int:
    try:
        import sqlite3
        c = sqlite3.connect(Path(out_dir) / "index.sqlite")
        n = c.execute("SELECT count(*) FROM records").fetchone()[0]
        c.close()
        return n
    except Exception:
        return -1


def write_report(out_dir: Path, mode: str, results: list, before: int, after: int):
    ts = datetime.now()
    day = ts.strftime("%Y-%m-%d")
    run_dir = out_dir / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"# 采集运行报告（{mode}）", "",
             f"- 时间：{ts.strftime('%Y-%m-%d %H:%M:%S')}",
             f"- 记录总数：{before} → {after}（新增 {after - before if before >= 0 else '?'}）", "",
             "| 阶段 | 结果 | 耗时s | 尾部输出 |", "|---|---|---|---|"]
    for r in results:
        tail = " / ".join(t[:60] for t in r["tail"]) or "-"
        lines.append(f"| {r['stage']} | {'✅' if r['ok'] else '❌'} | {r['seconds']} | {tail} |")
    lines.append("")
    report = "\n".join(lines)
    (run_dir / f"{ts.strftime('%Y%m%d_%H%M%S')}_{mode}.md").write_text(report, encoding="utf-8")
    heartbeat = {"last_run": ts.isoformat(timespec="seconds"), "mode": mode,
                 "last_success": ts.isoformat(timespec="seconds") if all(r["ok"] for r in results) else None,
                 "records": after, "stages": {r["stage"]: r["ok"] for r in results}}
    (out_dir / "heartbeat.json").write_text(json.dumps(heartbeat, ensure_ascii=False, indent=2),
                                            encoding="utf-8")
    print(report)


def process_alive(pid: int) -> bool:
    """进程存活探测；探测本身失败时按存活处理（宁可保守，不误删活锁）。"""
    try:
        if sys.platform == "win32":
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                               capture_output=True, text=True)
            return str(pid) in (r.stdout or "")
        os.kill(pid, 0)
        return True
    except Exception:
        return True


def main():
    ap = argparse.ArgumentParser(description="采集层统一入口")
    ap.add_argument("--mode", default="daily", choices=["daily", "manual", "backfill"])
    ap.add_argument("--only", default="", help="只跑指定阶段：xianzhi,rss,vuln,cnnvd,deepfill,report")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    lock = out_dir / ".run_daily.lock"
    out_dir.mkdir(parents=True, exist_ok=True)
    if lock.exists():
        # 死进程陈旧锁自动清理：进程被强杀时 finally 不执行，锁会残留（2026-10-06 实测坑）
        m = re.search(r"pid=(\d+)", lock.read_text())
        if m and not process_alive(int(m.group(1))):
            print(f"[lock] 发现死进程陈旧锁（pid={m.group(1)} 已不存在），自动清理。")
            lock.unlink(missing_ok=True)
        else:
            print(f"[lock] 已有运行在执行（{lock.read_text()}），退出。如确认无运行请删除锁文件。")
            return
    lock.write_text(f"pid={__import__('os').getpid()} at {now()}")
    log_dir = out_dir / "runs" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    stages = [s.strip() for s in args.only.split(",") if s.strip()] or \
             ["xianzhi", "rss", "vuln", "cnnvd", "deepfill", "export", "report"]
    try:
        before = db_count(out_dir)
        results = []

        # 阶段一：采集器并行（互相独立）
        collectors = [s for s in stages if s in COLLECTORS]
        if collectors:
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(collectors)) as ex:
                futs = {}
                for s in collectors:
                    cmd = list(COLLECTORS[s])
                    if s == "xianzhi" and args.mode == "backfill":
                        cmd += ["--full"]
                    if s == "rss" and args.mode == "backfill":
                        cmd += ["--lookback", "90"]
                    if s == "vuln" and args.mode == "backfill":
                        cmd += ["--lookback", "120"]
                    futs[ex.submit(run_stage, s, cmd, out_dir, log_dir)] = s
                for f in concurrent.futures.as_completed(futs):
                    res = f.result()
                    results.append(res)
                    print(f"[{res['stage']}] {'✅' if res['ok'] else '❌'} {res['seconds']}s")

        # 阶段二：正文补全（串行，限速；自动跳过 no_body 的微信记录）
        if "deepfill" in stages:
            results.append(run_stage("deepfill", ["scripts/deep_fill.py"], out_dir, log_dir))
            print(f"[deepfill] {'✅' if results[-1]['ok'] else '❌'} {results[-1]['seconds']}s")

        # 阶段三：导出 Markdown（产品形态：一次抓取+转换 md，按源分目录带 front-matter）
        if "export" in stages:
            results.append(run_stage("export", ["scripts/export_md.py"], out_dir, log_dir))
            print(f"[export] {'✅' if results[-1]['ok'] else '❌'} {results[-1]['seconds']}s")

        # 阶段四：报告 + 心跳
        after = db_count(out_dir)
        write_report(out_dir, args.mode, results, before, after)
    finally:
        lock.unlink(missing_ok=True)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    main()

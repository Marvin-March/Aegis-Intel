#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enrich_daily.py —— 加工层统一入口（采集之后的富化链，与 run_daily.py 配对）

设计：与 run_daily.py 解耦——采集永远准点完成，加工失败靠 checkpoint 第二天自动补，
     互不拖累（免费模型夜间不稳时不影响采集报告）。所有步骤幂等：
     字段空值 = 待处理，重复跑只处理增量，每天新增量只有几十条。

链路（例行跑法，顺序即依赖）：
    ① nvd_orphans   孤儿 CVE 按 ID 补 NVD 描述（有标签无文本的）
    ② nvd_external  库外引用回收（文章投票选出的采集线索 → NVD 补入库）
    ③ ai_review     AI 相关性三级复核（规则词→包名白名单→GLM，weak 池裁决）
    ④ enrich_l1     确定性富化五动作（CPE/GHA/正则抽CVE/论文匹配/零信号补扫）
    ⑤ enrich_llm    LLM 语义富化（CVE 中文摘要四件套 + 文章实体五元组）
    ⑥ data_clean    幂等清洗
    ⑦ export        全量导出 Markdown（与库对账的"印刷品"）
    ⑧ quality       质量面板

用法：
    uv run python scripts/enrich_daily.py                    # 全链（日常/定时任务用）
    uv run python scripts/enrich_daily.py --only ai_review   # 只跑某几步
    uv run python scripts/enrich_daily.py --mode manual      # 手动触发（报告标记）
依赖：GLM 步骤（③⑤）需要 .env 里的 GLM_API_KEY；无 key 时这两步报错但不阻塞其余步骤。
"""

import argparse
import io
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

# 顺序即依赖：补文本 → 补缺口 → 贴标签 → 确定性加工 → LLM 加工 → 清洗 → 导出 → 体检
# LLM 两步 2026-10-16 用户改定走 DeepSeek 官方（DEEPSEEK_API_KEY，问答同款 key）：
# 质量优于 glm-4-flash、无内容审核拦截（GLM 400/1301 会静默留空字段）、无限流降级损耗；
# 成本：夜间仅处理新增几十条，可忽略。火山方舟 key 账号未开通模型（ModelNotOpen），
# ARK_API_KEY 留在 .env 备用。glm 档保留为手动兜底（--provider glm）。
STEPS = [
    ("nvd_orphans", ["scripts/nvd_backfill_orphans.py"]),
    ("nvd_external", ["scripts/nvd_recover_external.py"]),
    ("ai_review", ["scripts/llm_review_weak.py", "--provider", "deepseek"]),
    ("enrich_l1", ["scripts/enrich_l1.py"]),
    ("enrich_llm", ["scripts/enrich_llm.py", "--kind", "all", "--provider", "deepseek"]),
    ("data_clean", ["scripts/data_clean.py"]),
    ("export", ["scripts/export_md.py"]),
    ("quality", ["scripts/quality_check.py"]),
]


def run_step(name: str, cmd: list, log_dir: Path, timeout: int = 7200) -> dict:
    t0 = time.time()
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    try:
        r = subprocess.run([PY, "-u"] + cmd, cwd=str(ROOT), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout, env=env)
        (log_dir / f"{name}.log").write_text(
            r.stdout[-20000:] + ("\n[STDERR]\n" + r.stderr[-5000:] if r.stderr else ""),
            encoding="utf-8")
        tail = [l for l in r.stdout.strip().splitlines() if l.strip()][-3:]
        return {"stage": name, "ok": r.returncode == 0, "seconds": round(time.time() - t0, 1),
                "tail": tail, "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired:
        return {"stage": name, "ok": False, "seconds": round(time.time() - t0, 1),
                "tail": [f"超时 {timeout}s"], "cmd": " ".join(cmd)}
    except Exception as e:
        return {"stage": name, "ok": False, "seconds": round(time.time() - t0, 1),
                "tail": [f"{type(e).__name__}: {e}"], "cmd": " ".join(cmd)}


def write_report(out_dir: Path, mode: str, results: list):
    ts = datetime.now()
    run_dir = out_dir / "runs"
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"# 富化链运行报告（{mode}）", "",
             f"- 时间：{ts.strftime('%Y-%m-%d %H:%M:%S')}", "",
             "| 步骤 | 结果 | 耗时s | 尾部输出 |", "|---|---|---|---|"]
    for r in results:
        tail = " / ".join(t[:60] for t in r["tail"]) or "-"
        lines.append(f"| {r['stage']} | {'✅' if r['ok'] else '❌'} | {r['seconds']} | {tail} |")
    lines.append("")
    (run_dir / f"{ts.strftime('%Y%m%d_%H%M%S')}_{mode}.md").write_text("\n".join(lines), encoding="utf-8")
    hb_p = out_dir / "heartbeat.json"
    hb = json.loads(hb_p.read_text(encoding="utf-8")) if hb_p.exists() else {}
    hb.update({"last_enrich": ts.isoformat(timespec="seconds"), "enrich_mode": mode,
               "enrich_ok": all(r["ok"] for r in results),
               "enrich_stages": {r["stage"]: r["ok"] for r in results}})
    hb_p.write_text(json.dumps(hb, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n".join(lines))


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
    ap = argparse.ArgumentParser(description="加工层（富化链）统一入口")
    ap.add_argument("--mode", default="daily", choices=["daily", "manual"])
    ap.add_argument("--only", default="", help="只跑指定步骤：nvd_orphans,nvd_external,ai_review,enrich_l1,enrich_llm,data_clean,export,quality")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    lock = out_dir / ".enrich_daily.lock"
    if lock.exists():
        # 死进程陈旧锁自动清理：进程被强杀时 finally 不执行，锁会残留（2026-10-06 实测坑）
        m = re.search(r"pid=(\d+)", lock.read_text())
        if m and not process_alive(int(m.group(1))):
            print(f"[lock] 发现死进程陈旧锁（pid={m.group(1)} 已不存在），自动清理。")
            lock.unlink(missing_ok=True)
        else:
            print(f"[lock] 已有富化链在执行（{lock.read_text()}），退出。如确认无运行请删除锁文件。")
            return
    lock.write_text(f"pid={os.getpid()} at {datetime.now():%Y-%m-%d %H:%M:%S}")
    log_dir = out_dir / "runs" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    wanted = [s.strip() for s in args.only.split(",") if s.strip()]
    steps = [s for s in STEPS if not wanted or s[0] in wanted]
    try:
        results = []
        for name, cmd in steps:
            print(f"[{name}] 开始…")
            res = run_step(name, cmd, log_dir)
            results.append(res)
            print(f"[{res['stage']}] {'✅' if res['ok'] else '❌'} {res['seconds']}s  " +
                  " / ".join(res["tail"][-1:]))
        write_report(out_dir, args.mode, results)
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nightly_pipeline.py —— 定时全链路包装（计划任务 Aegis-Intel-Full 的真实执行体）

为什么要有这层包装：collect_full.py 第 ④ 阶段（向量增量）要加载 8GB 嵌入模型，
与本机常驻 API（同样占 ~8GB）在 15.3GB 物理内存上必然冲突（2026-10-15 段错误实测）。
所以定时任务必须错峰：停 API → 全链路（采集→富化→切块→向量增量）→ 起 API。

流程：
  ① 停 API（按 :8000 端口找 PID，taskkill /T /F；未运行则跳过）
  ② python scripts/collect_full.py（四阶段，逐阶段日志/锁文件/超时保护，自带幂等）
  ③ 重启 API（DETACHED 脱离本进程，预热 ~60s 后可问答），并验证端口回监听

计划任务经 setup_schedule.py 注册，stdout 已被重定向到 data/runs/logs/scheduled_full.log。
用法：
    python scripts/nightly_pipeline.py             # 完整执行（定时任务用）
    python scripts/nightly_pipeline.py --dry-run   # 只打印将执行的步骤，不动任何进程
"""

import subprocess
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
API_LOG = ROOT / "data" / "runs" / "logs" / "api_nightly.log"


def find_api_pid() -> str | None:
    """从 netstat 找监听 :8000 的进程 PID；没有则 None。
    netstat 输出是 GBK（"活动连接"表头），必须按字节解码容错——text=True 会
    UnicodeDecodeError 且只崩读取线程，stdout 静默变空 → 误判 API 未运行。"""
    r = subprocess.run(["netstat", "-ano"], capture_output=True, timeout=30)
    out = (r.stdout or b"").decode("utf-8", errors="ignore")
    for line in out.splitlines():
        if ":8000" in line and "LISTENING" in line.upper():
            return line.split()[-1]
    return None


def stop_api() -> None:
    pid = find_api_pid()
    if not pid:
        print("[nightly] API 未在运行，无需停（内存全留给向量化）", flush=True)
        return
    subprocess.run(["taskkill", "/PID", pid, "/T", "/F"], capture_output=True, timeout=30)
    time.sleep(3)
    print(f"[nightly] 已停 API (PID {pid})，内存让给向量化阶段", flush=True)


def start_api() -> None:
    """启动 api.py 常驻。2026-10-16 改版：不再用 DETACHED_PROCESS——
    本机实测 DETACHED 拉起的 API 会无错误、零请求静默消失（两次复现），
    而普通 Popen（stdout 重定向文件）稳定。schtasks 任务进程退出后
    子进程在 Windows 上不被连坐杀死，普通模式即可常驻。"""
    API_LOG.parent.mkdir(parents=True, exist_ok=True)
    log = open(API_LOG, "ab")
    subprocess.Popen([PY, "-X", "utf8", "api.py"], cwd=str(ROOT / "scripts"),
                     stdout=log, stderr=subprocess.STDOUT,
                     close_fds=True)
    print(f"[nightly] API 已拉起（预热 ~60s），日志 {API_LOG.name}", flush=True)
    for i in range(12):                      # 最多等 96s 确认端口回监听
        time.sleep(8)
        if find_api_pid():
            print(f"[nightly] API 端口已回监听（{(i + 1) * 8}s），全链路收工", flush=True)
            return
    print("[nightly] 警告：96s 内未检测到 API 端口，请查看 api_nightly.log", flush=True)


def main() -> int:
    if "--dry-run" in sys.argv:
        pid = find_api_pid()
        print("[dry-run] ① 将停 API：" + (f"PID {pid}" if pid else "（当前未运行）"))
        print("[dry-run] ② 将执行：python -u scripts/collect_full.py"
              "（采集→富化→切块→向量增量，约 35-45 分钟）")
        print("[dry-run] ③ 将重启 API 并等待端口回监听")
        return 0

    t0 = time.time()
    print(f"\n[nightly] ===== 定时全链路开始 {time.strftime('%Y-%m-%d %H:%M:%S')} =====", flush=True)
    stop_api()
    r = subprocess.run([PY, "-u", "scripts/collect_full.py"], cwd=str(ROOT))
    print(f"[nightly] collect_full 退出码 {r.returncode}，耗时 "
          f"{round((time.time() - t0) / 60, 1)} 分钟", flush=True)
    start_api()
    print(f"[nightly] ===== 全链路结束 {time.strftime('%Y-%m-%d %H:%M:%S')}，"
          f"总耗时 {round((time.time() - t0) / 60, 1)} 分钟 =====", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup_schedule.py —— 一条命令把"每日全链路采集"注册到当前机器（Windows 计划任务）

这是自动化在部署代码中的体现：collect_full.py 是逻辑本体（采集→富化→切块→向量增量，
跑完新数据即可被问答命中），本脚本把它接进操作系统的调度器。换机器或部署到新环境时：

    uv sync                                  # ① 装依赖
    uv run playwright install chromium       # ② 装浏览器内核（采集用）
    copy .env.example .env                   # ③ 填 GLM_API_KEY（LLM 步骤用，可选）
    uv run python scripts/setup_schedule.py  # ④ 注册每日定时（本脚本）

★ 数据包可自带成品数据（index.sqlite + export/ + vector_store/），解压后即可问答，
  知识库不为空；定时任务接上后只在成品库基础上做每日增量（checkpoint 幂等）。
  --mode backfill 仅用于"空库从零部署"场景；已有数据包时无需执行。

注册内容（2026-10-16 起执行体改为 nightly_pipeline.py）：
    Aegis-Intel-Full  每天 05:00  nightly_pipeline.py
        = 停 API（向量化需 ~8GB 内存，与常驻 API 在 15.3GB 机器上冲突，2026-10-15 段错误实测）
        → collect_full.py：run_daily（四采集器并行+补正文+导出）→ enrich_daily（复核→富化→清洗→体检）
          → preprocess_corpus（切块）→ build_vector_wemm（向量增量，只嵌新块）
        → 重启 API（DETACHED，预热 ~60s 后可问答）
    正常增量约 35-45 分钟完成（采集 ~8min + 富化 ~20min + 切块 ~10s + 向量 ~10min），
    07:00 前新数据即可被问答命中。旧版两条任务（Collect/Enrich，缺向量增量）已废弃。

约束与自愈：
    - 息屏/锁屏不影响执行；关机需 05:00 开机，睡眠错过会在唤醒后自动补跑
      （StartWhenAvailable）；到点唤醒（WakeToRun）需系统电源计划允许唤醒定时器。
    - 与手动"立即采集"防撞：collect_full.py 检测到活锁自动退出，不会两链并行写库。
    - 富化 LLM 步骤失败不阻塞：字段空值=待处理，次日自动续。
查看 / 撤销：
    uv run python scripts/setup_schedule.py --status
    uv run python scripts/setup_schedule.py --remove
"""

import argparse
import io
import os
import subprocess
import sys
from pathlib import Path

# Windows GBK 编码兼容：强制 stdout 用 UTF-8
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent

TASKS = [
    # (任务名, 时间, 命令尾部)；全链路驱动 + 日志落盘（追加，跨日可追溯）
    # 执行体 2026-10-16 起为 nightly_pipeline.py：停 API → collect_full 四阶段 → 起 API
    # （向量化 8GB 内存与常驻 API 冲突，必须错峰——详见 nightly_pipeline.py 模块注释）
    # 05:00 起跑（2026-10-16 用户改定）：05:45 前全链路收工，06:00 后问答即可命中新数据
    ("Aegis-Intel-Full", "05:00", "scripts/nightly_pipeline.py"),
]
LOG_FILE = "data\\runs\\logs\\scheduled_full.log"


def tr_string(script: str) -> str:
    """任务动作：cd 到项目根后全部用相对路径（路径含空格也稳，且不超长）。"""
    py = Path(sys.executable)
    rel_py = ".venv" + chr(92) + "Scripts" + chr(92) + "python.exe" if py.parent.parent.name == ".venv" \
        else str(py)
    return (f'cd /d "{ROOT}" && "{rel_py}" -u {script.replace("/", chr(92))} '
            f'>> {LOG_FILE} 2>&1')


def register(name: str, st: str, script: str) -> bool:
    """PowerShell Register-ScheduledTask 注册（schtasks 无法设置下面三个选项）：
    StartWhenAvailable=错过补跑（睡眠错过 05:00，开机/唤醒后立即补）；
    WakeToRun=到点唤醒电脑（需系统电源计划允许唤醒定时器）；
    MultipleInstances IgnoreNew + ExecutionTimeLimit 6h=防重复实例与跑飞。"""
    arg = f'/c {tr_string(script)}'
    ps = (f"$a = New-ScheduledTaskAction -Execute 'cmd' -Argument '{arg}'; "
          f"$t = New-ScheduledTaskTrigger -Daily -At '{st}'; "
          f"$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun "
          f"-ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew; "
          f"Register-ScheduledTask -TaskName '{name}' -Action $a -Trigger $t -Settings $s -Force")
    # 全路径调 PowerShell：git-bash/精简 PATH 环境下裸名可能解析不到
    ps_exe = (Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
              / "WindowsPowerShell" / "v1.0" / "powershell.exe")
    r = subprocess.run([str(ps_exe), "-NoProfile", "-Command", ps],
                       capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"  {'✅' if ok else '❌'} {name}  {st}  →  {script}"
          + ("" if ok else f"\n     {r.stderr.strip() or r.stdout.strip()}"))
    return ok


def main():
    ap = argparse.ArgumentParser(description="注册/查看/撤销 每日全链路采集定时任务")
    ap.add_argument("--remove", action="store_true", help="撤销注册的任务")
    ap.add_argument("--status", action="store_true", help="只查看当前注册状态")
    args = ap.parse_args()

    if sys.platform != "win32":
        print("非 Windows：请用 crontab 接线（逻辑本体不变）：")
        for name, st, script in TASKS:
            h, m = st.split(":")
            print(f'  {m} {h} * * * cd "{ROOT}" && {sys.executable} {script} '
                  f'>> {ROOT / LOG_FILE} 2>&1')
        return

    if args.remove:
        for name, _, _ in TASKS:
            r = subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                               capture_output=True, text=True)
            print(f"  {'✅ 已撤销' if r.returncode == 0 else '（未注册或撤销失败）'} {name}")
        return

    if args.status:
        for name, st, script in TASKS:
            r = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, text=True)
            print(f"  {'✅ 已注册' if r.returncode == 0 else '⬜ 未注册'}  {name}  {st}  {script}")
        return

    print("注册每日定时任务（单任务全链路：采集→富化→切块→向量增量）：")
    all_ok = all(register(n, s, sc) for n, s, sc in TASKS)
    print()
    if all_ok:
        print("完成。日志：data/runs/logs/scheduled_full.log，报告：data/runs/。")
        print("注意：① LLM 步骤（AI 复核/富化）需要项目根目录 .env 里配好 GLM_API_KEY；")
        print("      ② 息屏不影响；睡眠错过会在唤醒后自动补跑；到点唤醒需电源计划允许唤醒定时器。")
    else:
        print("部分注册失败——多为权限不足，请用管理员身份重跑，或在任务计划程序 GUI 手动创建。")


if __name__ == "__main__":
    main()

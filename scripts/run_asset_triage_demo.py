#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_asset_triage_demo.py —— 一条命令跑通资产研判全链路。

从零开始：接入清单 → 同步真实公告 → 比对 → 生成工单 → 走完审批流（含证据失效驳回）。
不依赖主项目的向量库与 LLM，只需外网访问 api.github.com（或改用 --from-file 离线件）。

用法：
    python scripts/run_asset_triage_demo.py
    python scripts/run_asset_triage_demo.py --skip-sync --from-file advisories.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "scripts" / "asset_triage_cli.py"
DEFAULT_OUT = ROOT / "data" / "triage_demo"


def run(args: list[str], title: str) -> tuple[int, str]:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")
    p = subprocess.run([sys.executable, *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    print(out.strip())
    return p.returncode, out


def _default_inventory() -> Path:
    """找演示清单：优先仓库内 demo/，其次同级 aegis-asset-triage/demo/。

    队友拿到的 zip 解压后素材就在 demo/，所以仓库内的路径要优先。
    """
    for cand in (ROOT / "demo" / "assets.csv",
                 ROOT.parent / "aegis-asset-triage" / "demo" / "assets.csv"):
        if cand.exists():
            return cand
    return ROOT / "demo" / "assets.csv"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--inventory", type=Path, default=None)
    ap.add_argument("--from-file", type=Path, default=None, help="离线公告 JSON")
    ap.add_argument("--skip-sync", action="store_true")
    ap.add_argument("--max-pages", type=int, default=2)
    args = ap.parse_args()
    if args.inventory is None:
        args.inventory = _default_inventory()

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    db = out / "triage.sqlite"
    if db.exists():
        db.unlink()                      # 演示库每次重建，保证结果可复现
    base = [str(CLI), "--db", str(db)]

    inv = args.inventory
    if not inv.exists():
        print(f"[demo] 找不到资产清单 {inv}")
        print("[demo] 可先运行：python scripts/asset_triage_cli.py import <你的清单>")
        return 1

    # 1. 接入
    rc, _ = run(base + ["import", str(inv)], "① 接入企业组件与版本清单")
    if rc != 0:
        return rc

    # 2. 同步
    if not args.skip_sync:
        if args.from_file:
            rc, _ = run(base + ["sync", "--from-file", str(args.from_file)],
                        "② 同步结构化版本区间（离线件）")
        else:
            rc, _ = run(base + ["sync", "--source", "ghsa", "--max-pages", str(args.max_pages)],
                        "② 同步结构化版本区间（GHSA）")
        if rc != 0:
            print("[demo] 同步失败；内网环境请用 --from-file 提供离线公告")
            return rc

    # 3. 比对
    rc, _ = run(base + ["match", "--out-dir", str(out)], "③ 资产 × 公告确定性比对")
    if rc != 0:
        return rc

    # 4. 草稿
    rc, draft_out = run(base + ["draft", "--approver", "周敏", "--actor", "系统",
                                "--out-dir", str(out / "tickets")], "④ 生成带证据的变更工单草稿")
    if rc != 0:
        return rc

    tickets = json.loads((out / "tickets" / "tickets.json").read_text(encoding="utf-8"))
    if not tickets:
        print("[demo] 未生成工单")
        return 1

    # 5. 走完一张单的完整审批流（选优先级最高的一张，负责人≠审批人）
    target = sorted(tickets, key=lambda t: t["priority"])[0]
    tid, owner = target["ticket_id"], target["owner"]
    tdir = str(out / "tickets")
    run(base + ["submit", "--ticket", tid, "--actor", owner,
                "--comment", "已确认受影响资产，申请升级", "--out-dir", tdir],
        f"⑤ 负责人 {owner} 提交审批 {tid}")
    run(base + ["decide", "--ticket", tid, "--approver", "周敏", "--approve",
                "--comment", "同意，安排在下一个变更窗口", "--out-dir", tdir],
        "⑥ 审批人 周敏 审批通过")

    # 6. 关闭已批准的工单（完成闭环）
    run(base + ["close", "--ticket", tid, "--actor", owner,
                "--comment", "已按方案升级并复跑比对，确认不再命中", "--out-dir", tdir],
        f"⑦ 负责人 {owner} 关闭 {tid}")

    # 7. 演示「证据失效」防护：另一张单在审批前资产已被升级
    others = [t for t in tickets if t["ticket_id"] != tid and t["status"] == "draft"]
    if others:
        t2 = others[0]
        run(base + ["submit", "--ticket", t2["ticket_id"], "--actor", t2["owner"],
                    "--comment", "申请升级", "--out-dir", tdir],
            f"⑧ 提交另一张单 {t2['ticket_id']}")
        ids = json.loads(t2["finding_ids"])
        sys.path.insert(0, str(ROOT / "scripts"))
        from asset_triage import Store
        s = Store(db)
        first = s.findings_by_ids(ids)[0]
        s.db.execute("UPDATE asset_component SET version=? WHERE asset_id=?",
                     (first["first_patched"] or "999.0.0", first["asset_id"]))
        s.db.commit()
        s.close()
        print(f"\n[demo] 模拟变更窗口：资产 {first['asset_id']} 已被升级到 "
              f"{first['first_patched'] or '999.0.0'}")
        run(base + ["decide", "--ticket", t2["ticket_id"], "--approver", "周敏",
                    "--approve", "--comment", "同意", "--out-dir", tdir],
            "⑨ 审批该单 —— 应因证据失效被自动驳回")

    # 8. 汇总
    run(base + ["list", "tickets"], "⑩ 最终工单状态")
    print(f"\n[demo] 产物目录：{out}")
    print(f"[demo]   findings.json    受影响结论与统计")
    print(f"[demo]   tickets/*.md     工单正文（含证据与审批留痕）")
    print(f"[demo]   triage.sqlite    完整库（可直接接 API）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

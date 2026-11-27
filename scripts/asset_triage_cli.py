#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""asset_triage_cli.py —— 资产暴露面研判命令行入口

把情报库接到企业组件清单，跑通五步：
  1. import  接入资产清单（CSV/JSON / CycloneDX SBOM / pip freeze）
  2. sync    拉取带结构化版本区间的公告（GHSA / OSV / 本地导出）
  3. match   资产 × 公告确定性比对，产出带证据的受影响结论
  4. draft   按负责人聚合生成变更工单草稿（Markdown + JSON）
  5. approve 提交审批 / 审批决定 / 关闭（含证据失效自动驳回）

示例：
  python scripts/asset_triage_cli.py import demo/assets.csv
  python scripts/asset_triage_cli.py sync --packages vllm,langchain --max-pages 1
  python scripts/asset_triage_cli.py match --out-dir data/triage
  python scripts/asset_triage_cli.py draft --priority P1,P2 --owner 张三 --approver 李四
  python scripts/asset_triage_cli.py submit --ticket CHG-XXXX --actor 张三
  python scripts/asset_triage_cli.py decide --ticket CHG-XXXX --approver 李四 --approve --comment "同意"
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import sqlite3
import sys
from contextlib import closing
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from asset_triage import Store
from asset_triage import discovery
from asset_triage.ingest import load_auto
from asset_triage.matcher import dedupe_findings, match, now_iso
from asset_triage.models import clean_version, norm_package, normalize_range, RangeParseError
from asset_triage.sources import fetch_ghsa, fetch_osv, load_advisory_rows
from asset_triage import tickets as tk

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "index.sqlite"


def _store(args) -> Store:
    return Store(args.db or DEFAULT_DB)


# ------------------------------------------------------------------ import

def cmd_import(args) -> int:
    store = _store(args)
    assets, errors = load_auto(args.path)
    if not assets:
        print(f"[import] 未读到有效资产；拒绝项 {len(errors)}")
        for e in errors[:10]:
            print("  -", e)
        return 1
    rows = []
    for a in assets:
        d = a.__dict__.copy()
        d["evidence_json"] = json.dumps({"ingest": str(args.path), "source": a.source},
                                        ensure_ascii=False)
        rows.append(d)
    n = store.upsert_assets(rows, now_iso())
    print(f"[import] 入库 {n} 条资产（原始 {len(assets) + len(errors)} 行）")
    if errors:
        print(f"[import] 拒收 {len(errors)} 行，前 5 条：")
        for e in errors[:5]:
            print("  -", e)
    apps = sorted({a.app_name for a in assets if a.app_name})
    print(f"[import] 覆盖应用 {len(apps)} 个：{', '.join(apps[:8]) or '-'}")
    store.close()
    return 0


# --------------------------------------------------------- 自动识别与人工审核

def cmd_discover(args) -> int:
    scope = discovery.validate_scope(args.scope)
    if args.report_only and not args.report:
        raise ValueError("--report-only 需要指定 --report")
    if args.report:
        inputs = [args.db or DEFAULT_DB]
        if args.npm_lock:
            inputs.append(args.npm_lock)
        if args.report.resolve() in {path.resolve() for path in inputs}:
            raise ValueError("报告路径须与数据库、锁文件不同")

    observations = []
    if args.python_current or args.python_site or not args.npm_lock:
        observations.extend(discovery.python_observations(args.python_site))
    if args.npm_lock:
        observations.extend(discovery.npm_observations(args.npm_lock))
    listeners = discovery.local_tcp_listeners() if args.listeners else None
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    host = socket.gethostname()
    observations = [replace(item, collector_host=host) for item in observations]
    if args.report_only:
        print(f"[discover] {scope}: 采集到 {len(observations)} 条组件观测")
    else:
        _stage_report(args, scope, now, observations, "discover")
    if args.report:
        report = {
            "schema_version": 1,
            "scope": scope,
            "collected_at": now,
            "collector_host": host,
            "observations": [asdict(item) for item in observations],
            "local_tcp_listeners": listeners,
        }
        _write(args.report, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"[discover] 本机采集报告 → {args.report}")
    elif listeners is not None:
        print(json.dumps(listeners, ensure_ascii=False, indent=2))
    return 0


def _stage_report(args, scope, now, observations, command):
    with closing(_store(args)) as store:
        count = discovery.stage_observations(store, scope, observations, now, ordered_snapshot=True)
        pending = store.db.execute(
            "SELECT count(*) FROM asset_candidate WHERE scope=? AND status='pending'", (scope,),
        ).fetchone()[0]
    print(f"[{command}] {scope}: 本次处理 {count} 个组件，当前 {pending} 条待确认")


def cmd_discover_import(args) -> int:
    if args.path.resolve() == (args.db or DEFAULT_DB).resolve():
        raise ValueError("报告路径须与数据库不同")
    scope, now, observations = discovery.read_report(args.path)
    if args.scope is not None and scope != args.scope:
        raise ValueError("报告的部署标识与 --scope 不一致")
    _stage_report(args, scope, now, observations, "discover-import")
    return 0


def cmd_review_export(args) -> int:
    if args.out.resolve() == (args.db or DEFAULT_DB).resolve():
        raise ValueError("审核表路径须与数据库不同")
    with closing(_store(args)) as store:
        count = discovery.export_review(store, args.out, args.scope, include_reviewed=args.include_reviewed)
    print(f"[review-export] {count} 条候选 → {args.out}")
    return 0


def cmd_review_apply(args) -> int:
    with closing(_store(args)) as store:
        counts = discovery.apply_reviews(store, args.path, args.actor, now_iso())
    print(f"[review-apply] 确认 {counts['confirm']}，驳回 {counts['reject']}，补录 {counts['add']}")
    return 0


# ------------------------------------------------------------------ sync

def _pairs(store: Store, packages: str | None) -> list[tuple[str, str]]:
    if packages:
        out = []
        for p in packages.split(","):
            p = p.strip()
            if not p:
                continue
            if ":" in p:
                eco, name = p.split(":", 1)
            else:
                eco, name = "pypi", p
            out.append((eco, name))
        return out
    # 默认跟随已接入清单里的组件，避免拉一堆用不上的公告
    assets = store.list_assets(confirmed_only=True)
    return sorted({(a["ecosystem"], a["component"]) for a in assets})


def cmd_sync(args) -> int:
    store = _store(args)
    if args.from_file:
        rows = load_advisory_rows(args.from_file)
        warnings = []
    else:
        pairs = _pairs(store, args.packages)
        if not pairs:
            print("[sync] 没有已确认资产且未指定 --packages，请先审核候选或导入台账")
            return 1
        print(f"[sync] 组件 {len(pairs)} 个：{', '.join(p for _, p in pairs[:10])}")
        rows, warnings = [], []
        if args.source in {"ghsa", "all"}:
            r, w = fetch_ghsa(pairs, per_page=args.per_page, max_pages=args.max_pages)
            rows += r
            warnings += w
            print(f"[sync] ghsa 拉到 {len(r)} 条组件区间")
        if args.source in {"osv", "all"}:
            r, w = fetch_osv(pairs)
            rows += r
            warnings += w
            print(f"[sync] osv 拉到 {len(r)} 条组件区间")

    # 归一化区间：能解析的写入 range_normalized，不能解析的留空但仍入库（供人工复核）
    ok = bad = 0
    now = now_iso()
    for r in rows:
        r["fetched_at"] = now
        try:
            r["range_normalized"] = normalize_range(r["range_raw"], r["ecosystem"])
            r["first_patched"] = clean_version(r.get("first_patched") or "")
            ok += 1
        except RangeParseError:
            bad += 1
    n = store.upsert_advisories(rows)
    print(f"[sync] 入库 {n} 条区间（可解析 {ok}，不可解析 {bad}）")
    if warnings:
        print(f"[sync] 告警 {len(warnings)} 条：")
        for w in warnings[:8]:
            print("  -", w)
    store.close()
    return 0


# ------------------------------------------------------------------ match

def _write(path: Path, text: str) -> None:
    """统一以 LF 写盘。

    Path.write_text 在 Windows 上会把 \\n 转成 \\r\\n，而仓库 .gitattributes 约定
    `*.md eol=lf`、`*.py text eol=lf`。工单 Markdown 要进 Git 或贴进 ITSM，
    换行符漂移会制造无意义的 diff，这里显式固定。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


def cmd_match(args) -> int:
    store = _store(args)
    assets = store.list_assets(confirmed_only=True)
    if not assets:
        print("[match] 没有可研判的已确认资产，请审核候选或导入已核实台账")
        store.close()
        return 1
    advisories = [dict(r) for r in store.db.execute("SELECT * FROM advisory_range")]
    if not advisories:
        print("[match] 公告区间为空，先执行 sync")
        return 1

    findings, stats, problems = match(assets, advisories,
                                      run_id=args.run_id)
    if args.dedupe:
        before = len(findings)
        findings = dedupe_findings(findings)
        print(f"[match] 同 CVE 去重 {before} → {len(findings)}")
    store.replace_findings(args.run_id or f"run-{now_iso()}", findings)

    out_dir = Path(args.out_dir) if args.out_dir else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        _write(out_dir / "findings.json",
               json.dumps({"stats": stats.as_dict(), "findings": findings},
                          ensure_ascii=False, indent=2))
        _write(out_dir / "parse_problems.json",
               json.dumps(problems, ensure_ascii=False, indent=2))

    print(f"[match] 资产 {stats.assets} × 公告 {stats.advisories} 条区间；"
          f"比对 {stats.pairs_checked} 对，命中 {stats.findings}")
    print(f"[match] 区间不可解析 {stats.unparsed_ranges}，版本不可解析 {stats.unparsed_versions}")
    for f in findings[:15]:
        print(f"  - {f['priority']} {f['severity']:<8} {f['component']} {f['installed_version']}"
              f"  ←  {f['cve_id'] or f['advisory_id']}  ({f['range_raw']})")
    if len(findings) > 15:
        print(f"  ... 其余 {len(findings) - 15} 条见 findings.json")
    store.close()
    return 0


# ------------------------------------------------------------------ draft / render

def cmd_draft(args) -> int:
    store = _store(args)
    prios = [p.strip().upper() for p in (args.priority or "P1,P2,P3,P4").split(",")]
    findings = [f for f in store.list_findings() if f["priority"] in prios and f["status"] == "open"]
    if not findings:
        print("[draft] 没有符合条件的 open 结论")
        return 1
    result = tk.build_draft(store, [f["finding_id"] for f in findings],
                            approver=args.approver, actor=args.actor)
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "data" / "triage"
    out_dir.mkdir(parents=True, exist_ok=True)

    created = []
    for t in result["tickets"]:
        store.insert_ticket(t)
        store.add_event(t["ticket_id"], "create", args.actor or "system", "system",
                        "由资产暴露面研判生成草稿", "", "draft", now_iso())
        ids = json.loads(t["finding_ids"])
        md = tk.render_markdown(t, store.findings_by_ids(ids), store.ticket_events(t["ticket_id"]))
        _write(out_dir / f"{t['ticket_id']}.md", md)
        created.append(t)
        print(f"[draft] {t['ticket_id']}  {t['priority']}  {t['owner']:<6} "
              f"{len(ids)} 项受影响  {t['title'][:60]}")
    _write(out_dir / "tickets.json", json.dumps(created, ensure_ascii=False, indent=2))
    print(f"[draft] 生成 {len(created)} 张草稿 → {out_dir}")
    store.close()
    return 0


def _export_ticket_md(store: Store, ticket_id: str, out_dir: Path) -> Path:
    """把工单重新渲染到磁盘。状态变更后必须重导，否则 Markdown 停在草稿态，
    审阅者看到的审批记录与库里不一致。"""
    t = store.get_ticket(ticket_id)
    if not t:
        raise ValueError(f"工单不存在: {ticket_id}")
    ids = json.loads(t.get("finding_ids") or "[]")
    md = tk.render_markdown(t, store.findings_by_ids(ids), store.ticket_events(ticket_id))
    p = out_dir / f"{ticket_id}.md"
    _write(p, md)
    return p


def _resolve_out_dir(args) -> Path:
    if getattr(args, "out_dir", ""):
        return Path(args.out_dir)
    return ROOT / "data" / "triage"


def cmd_show(args) -> int:
    store = _store(args)
    t = store.get_ticket(args.ticket)
    if not t:
        print(f"[show] 工单不存在: {args.ticket}")
        return 1
    ids = json.loads(t["finding_ids"])
    print(tk.render_markdown(t, store.findings_by_ids(ids), store.ticket_events(args.ticket)))
    store.close()
    return 0


# ------------------------------------------------------------------ 审批

def cmd_submit(args) -> int:
    store = _store(args)
    try:
        t = tk.submit(store, args.ticket, args.actor or "unknown", args.comment or "")
    except Exception as e:
        print(f"[submit] 拒绝：{type(e).__name__}: {e}")
        store.close()
        return 2
    p = _export_ticket_md(store, args.ticket, _resolve_out_dir(args))
    print(f"[submit] {t['ticket_id']} → {t['status']}（审批人 {t['approver']}）；已更新 {p.name}")
    store.close()
    return 0


def cmd_decide(args) -> int:
    store = _store(args)
    try:
        t = tk.decide(store, args.ticket, args.approver, args.approve, args.comment or "")
    except Exception as e:
        # 自动驳回也会改状态，同样需要重导，否则磁盘上还是 pending
        try:
            _export_ticket_md(store, args.ticket, _resolve_out_dir(args))
        except Exception:
            pass
        print(f"[decide] 拒绝：{type(e).__name__}: {e}")
        store.close()
        return 2
    p = _export_ticket_md(store, args.ticket, _resolve_out_dir(args))
    print(f"[decide] {t['ticket_id']} → {t['status']}（{args.approver}）；已更新 {p.name}")
    store.close()
    return 0


def cmd_close(args) -> int:
    store = _store(args)
    try:
        t = tk.close(store, args.ticket, args.actor or "unknown", args.comment or "")
    except Exception as e:
        print(f"[close] 拒绝：{type(e).__name__}: {e}")
        store.close()
        return 2
    p = _export_ticket_md(store, args.ticket, _resolve_out_dir(args))
    print(f"[close] {t['ticket_id']} → {t['status']}；已更新 {p.name}")
    store.close()
    return 0


def cmd_list(args) -> int:
    store = _store(args)
    if args.what == "assets":
        rows = store.list_assets(confirmed_only=True)
        print(f"{'资产ID':<28}{'应用':<18}{'组件':<22}{'版本':<14}{'负责人':<8}{'重要度'}")
        for a in rows:
            print(f"{a['asset_id'][:27]:<28}{(a['app_name'] or '-')[:17]:<18}"
                  f"{a['component'][:21]:<22}{a['version'][:13]:<14}"
                  f"{(a['owner'] or '-')[:7]:<8}{a['criticality']}")
    elif args.what == "findings":
        rows = store.list_findings(priority=args.priority)
        print(f"共 {len(rows)} 条受影响结论")
        for f in rows[:40]:
            print(f"{f['priority']} {f['severity']:<8} {f['asset_id'][:20]:<22}"
                  f"{f['component']} {f['installed_version']} ← {f['cve_id'] or f['advisory_id']}")
    else:
        rows = store.list_tickets(status=args.status)
        print(f"共 {len(rows)} 张工单")
        for t in rows:
            print(f"{t['ticket_id']} {t['status']:<16}{t['priority']}  "
                  f"{(t['owner'] or '-')[:8]:<10}{t['title'][:60]}")
    store.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Aegis Intel 资产暴露面研判")
    ap.add_argument("--db", type=Path, default=None, help=f"SQLite 路径（默认 {DEFAULT_DB}）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("import", help="接入资产清单")
    p.add_argument("path", type=Path)
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("discover", help="只读采集本机组件与可选监听信息")
    p.add_argument("--scope", required=True, help="稳定的部署标识，如 ai-api-prod-01")
    python_source = p.add_mutually_exclusive_group()
    python_source.add_argument("--python-current", action="store_true", help="读取当前 Python 环境")
    python_source.add_argument("--python-site", action="append", default=[], type=Path,
                               help="读取指定环境的 site-packages，可重复")
    p.add_argument("--npm-lock", type=Path, help="读取 package-lock.json 的构建版本")
    p.add_argument("--listeners", action="store_true", help="读取本机 TCP 监听状态，需 psutil")
    p.add_argument("--report", type=Path, help="可选的 JSON 采集报告路径")
    p.add_argument("--report-only", action="store_true", help="只写 JSON 报告，不打开资产库")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("discover-import", help="导入其他部署的离线采集报告")
    p.add_argument("path", type=Path)
    p.add_argument("--scope", help="校验报告对应的部署标识")
    p.set_defaults(func=cmd_discover_import)

    p = sub.add_parser("review-export", help="导出待人工确认的候选到 CSV")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--scope", help="只导出指定部署的候选")
    p.add_argument("--include-reviewed", action="store_true", help="包括已审核记录，供人工纠正")
    p.set_defaults(func=cmd_review_export)

    p = sub.add_parser("review-apply", help="应用审核表中的确认、驳回和手工补录")
    p.add_argument("path", type=Path)
    p.add_argument("--actor", required=True)
    p.set_defaults(func=cmd_review_apply)

    p = sub.add_parser("sync", help="拉取结构化版本区间公告")
    p.add_argument("--source", choices=["ghsa", "osv", "all"], default="ghsa")
    p.add_argument("--packages", type=str, default="", help="逗号分隔，如 vllm,langchain 或 npm:openai")
    p.add_argument("--from-file", type=Path, default=None, help="离线 JSON 公告导出件")
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--max-pages", type=int, default=2)
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("match", help="资产 × 公告比对")
    p.add_argument("--out-dir", type=str, default="")
    p.add_argument("--run-id", type=str, default="")
    p.add_argument("--dedupe", action="store_true", default=True)
    p.set_defaults(func=cmd_match)

    p = sub.add_parser("draft", help="生成变更工单草稿")
    p.add_argument("--priority", type=str, default="P1,P2,P3,P4")
    p.add_argument("--approver", type=str, default="")
    p.add_argument("--actor", type=str, default="")
    p.add_argument("--out-dir", type=str, default="")
    p.set_defaults(func=cmd_draft)

    p = sub.add_parser("show", help="查看工单正文")
    p.add_argument("--ticket", required=True)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("submit", help="提交审批")
    p.add_argument("--ticket", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--comment", default="")
    p.add_argument("--out-dir", type=str, default="", help="工单 Markdown 输出目录")
    p.set_defaults(func=cmd_submit)

    p = sub.add_parser("decide", help="审批决定")
    p.add_argument("--ticket", required=True)
    p.add_argument("--approver", required=True)
    p.add_argument("--approve", action="store_true")
    p.add_argument("--comment", default="")
    p.add_argument("--out-dir", type=str, default="", help="工单 Markdown 输出目录")
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("close", help="关闭工单")
    p.add_argument("--ticket", required=True)
    p.add_argument("--actor", required=True)
    p.add_argument("--comment", default="")
    p.add_argument("--out-dir", type=str, default="", help="工单 Markdown 输出目录")
    p.set_defaults(func=cmd_close)

    p = sub.add_parser("list", help="查看资产/结论/工单")
    p.add_argument("what", choices=["assets", "findings", "tickets"])
    p.add_argument("--priority", default="")
    p.add_argument("--status", default="")
    p.set_defaults(func=cmd_list)

    args = ap.parse_args()

    if args.cmd in {"discover", "discover-import", "review-export", "review-apply"}:
        try:
            return args.func(args)
        except (OSError, ValueError, csv.Error, sqlite3.Error) as exc:
            print(f"[{args.cmd}] {exc}", file=sys.stderr)
            return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

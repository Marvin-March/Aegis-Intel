#!/usr/bin/env python3
"""采集客户 AI 组件，按已确认版本筛选并推送重点情报。"""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import sys
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from asset_triage import discovery
from asset_triage.customer_intel import (
    DEFAULT_CATALOG, confirmed_components, customer_scope, focus_alerts, load_catalog,
)
from asset_triage.store import Store
from asset_triage_cli import DEFAULT_DB, cmd_sync as sync_advisories
from customer_intel_transport.integration_common import (
    Delivery, DispatchLog, endpoint_identity, http_url, load_env, target_key,
)
from customer_intel_transport.notify_im import WEBHOOK_ENV, build_im_payload, send_im


def collect(args, catalog) -> int:
    scope = customer_scope(args.customer, args.deployment)
    if args.from_report:
        reported_scope, collected_at, observations = discovery.read_report(args.from_report)
        if reported_scope not in {args.deployment, scope}:
            raise ValueError("报告的部署标识与 --deployment 不一致")
        ecosystems = {item.ecosystem for item in observations}
    else:
        observations = []
        ecosystems = set()
        if args.python_site or args.python_current or not args.npm_lock:
            observations.extend(discovery.python_observations(args.python_site))
            ecosystems.add("pypi")
        if args.npm_lock:
            observations.extend(discovery.npm_observations(args.npm_lock))
            ecosystems.add("npm")
        hostname = socket.gethostname()
        observations = [replace(item, collector_host=hostname) for item in observations]
        collected_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    scoped_catalog = {(eco, name) for eco, name in catalog if eco in ecosystems}
    selected = [item for item in observations if (item.ecosystem, item.component) in scoped_catalog]
    with closing(Store(args.db)) as store:
        discovery.stage_observations(
            store, scope, selected, collected_at, ordered_snapshot=True, reviewed_catalog=scoped_catalog,
        )
        pending = store.db.execute(
            "SELECT count(*) FROM asset_candidate WHERE scope=? AND status='pending'", (scope,),
        ).fetchone()[0]
    print(f"{scope}: 识别 {len({(item.ecosystem, item.component) for item in selected})} 个 AI 组件，待确认 {pending} 条")
    return 0


def sync(args, catalog) -> int:
    with closing(Store(args.db)) as store:
        owned = confirmed_components(store.db, args.customer, catalog)
    if not owned:
        print("该客户当前没有已确认的 AI 组件")
        return 1
    args.packages = ",".join(sorted({f"{item['ecosystem']}:{item['component']}" for item in owned}))
    return sync_advisories(args)


def _select(log, platform, key, alerts, limit):
    statuses = log.statuses(platform, key)
    candidates = [item for item in alerts if statuses.get(item.event_id) in {None, "failed"}]
    return sorted(candidates, key=lambda item: item.event_id in statuses)[:limit]


def push(args, catalog) -> int:
    env = load_env(args.env_file) if args.env_file else {}
    endpoint = env.get(WEBHOOK_ENV[args.platform])
    if args.send and (not args.env_file or not endpoint):
        raise ValueError("发送时需要该客户独立的 --env-file 及对应机器人地址")
    if args.env_file and env.get("AEGIS_CUSTOMER_ID") != args.customer:
        raise ValueError("机器人配置的 AEGIS_CUSTOMER_ID 必须与 --customer 一致")
    endpoint = http_url(endpoint) if endpoint else None
    # 单独的命名空间使项目原有全量告警和客户通知互不覆盖发送记录。
    key = target_key({}, f"customer-ai:{args.customer}:{endpoint_identity(endpoint) if endpoint else 'preview'}")
    if not args.db.is_file():
        raise ValueError("索引库不存在，请先采集并确认客户组件")
    uri = args.db.resolve().as_uri() + ("?mode=rw" if args.send else "?mode=ro")
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        db.row_factory = sqlite3.Row
        # push 预演使用只读连接，兼容尚未安装客户资产模块的数据库。
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='asset_candidate'",
        ).fetchone()
        if not exists:
            raise ValueError("索引库中还没有客户资产清单，请先运行 collect")
        owned = confirmed_components(db, args.customer, catalog)
        alerts, unparsed = focus_alerts(db, owned, args.min_cvss, args.since_days)
        log = DispatchLog(db, writable=args.send)
        candidates = _select(log, args.platform, key, alerts, args.max_items)
        if not args.send:
            print(json.dumps({
                "customer": args.customer,
                "platform": args.platform,
                "confirmed_components": len(owned),
                "unparsed_pairs": unparsed,
                "alerts": [{
                    "notice": item.cve_id,
                    "evidence": item.details(),
                    "payload": build_im_payload(args.platform, item),
                } for item in candidates],
            }, ensure_ascii=False, indent=2))
            return 0
        pending = log.claim(args.platform, key, [item.event_id for item in candidates])
        selected = {item.event_id: item for item in candidates}
        totals = {"sent": 0, "failed": 0, "uncertain": 0}
        for event_id in pending:
            try:
                result = send_im(args.platform, selected[event_id], env, timeout=10)
            except Exception:
                # 发送请求可能已经到达。留作人工确认，避免盲重发。
                result = Delivery("uncertain")
            log.finish(args.platform, key, {event_id: result})
            totals[result.status] += 1
        print(json.dumps({"customer": args.customer, "unparsed_pairs": unparsed, **totals}, ensure_ascii=False))
        return 1 if totals["failed"] or totals["uncertain"] else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--category", action="append", default=[], help="例如 security，可重复")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect", help="采集指定客户的 AI 组件候选")
    p.add_argument("--customer", required=True)
    p.add_argument("--deployment", required=True)
    p.add_argument("--from-report", type=Path)
    sources = p.add_mutually_exclusive_group()
    sources.add_argument("--python-current", action="store_true")
    sources.add_argument("--python-site", action="append", type=Path, default=[])
    p.add_argument("--npm-lock", type=Path)
    p.set_defaults(func=collect)

    p = sub.add_parser("sync", help="同步客户已确认 AI 组件的公告")
    p.add_argument("--customer", required=True)
    p.add_argument("--source", choices=["ghsa", "osv", "all"], default="ghsa")
    p.add_argument("--from-file", type=Path, help="使用已有的离线公告文件")
    p.add_argument("--per-page", type=int, default=100)
    p.add_argument("--max-pages", type=int, default=2)
    p.set_defaults(func=sync)

    p = sub.add_parser("push", help="预演或推送客户重点情报")
    p.add_argument("--customer", required=True)
    p.add_argument("--platform", choices=list(WEBHOOK_ENV), default="wecom")
    p.add_argument("--env-file", type=Path)
    p.add_argument("--min-cvss", type=float, default=7.0)
    p.add_argument("--since-days", type=int, default=0, help="0 包含历史公告")
    p.add_argument("--max-items", type=int, default=20)
    p.add_argument("--send", action="store_true", help="发送真实机器人消息；默认只预演")
    p.set_defaults(func=push)

    args = parser.parse_args(argv)
    if args.command == "push":
        if not 0 <= args.min_cvss <= 10 or not 0 <= args.since_days <= 36500 or args.max_items < 1:
            parser.error("推送阈值、时间窗口或数量不合法")
    if args.command == "collect" and args.from_report and (args.python_current or args.python_site or args.npm_lock):
        parser.error("--from-report 与本机采集参数不能同时使用")
    try:
        catalog = load_catalog(args.catalog, args.category)
        return args.func(args, catalog)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"[{args.command}] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

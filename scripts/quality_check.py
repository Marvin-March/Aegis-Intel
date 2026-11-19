#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
quality_check.py —— 情报数据核查工具（对应《docs/quality.md》§一/§二/§四）

用法：
    uv run python scripts/quality_check.py                    # 例行核查（§一 全项+面板）
    uv run python scripts/quality_check.py --sample 5         # 追加抽样 5 条（§二 人工审读辅助）
    uv run python scripts/quality_check.py --vector-ready     # 向量化前专项（§四 追加项）
"""
import argparse
import random
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DB = "data/index.sqlite"


def check_routine(db):
    """§一 例行核查，返回 (全绿?, 详情列表)。"""
    checks = [
        ("拦截页-滑块", "SELECT count(*) FROM records WHERE content_md LIKE '%请按住滑块%' OR content_md LIKE '%拖动到最右边%'"),
        ("拦截页-环境异常", "SELECT count(*) FROM records WHERE content_md LIKE '%环境异常%' AND type IN ('article','rss_article')"),
        ("拦截页-访问频繁", "SELECT count(*) FROM records WHERE content_md LIKE '%访问过于频繁%'"),
        ("enriched<300字", "SELECT count(*) FROM records WHERE status='enriched' AND type IN ('article','rss_article') AND length(content_md)<300"),
        ("type空", "SELECT count(*) FROM records WHERE type IS NULL OR type=''"),
        ("未来日期", f"SELECT count(*) FROM records WHERE publish_time > '{datetime.now().strftime('%Y-%m-%d %H:%M')}'"),
        ("付费有正文", "SELECT count(*) FROM records WHERE tags LIKE '%付费%' AND length(content_md)>0"),
        ("no_body有正文", "SELECT count(*) FROM records WHERE status='no_body' AND length(content_md)>0"),
        ("url重复行", "SELECT count(*) FROM (SELECT url FROM records GROUP BY url HAVING count(*)>1)"),
        ("CVE编号格式", "SELECT count(*) FROM records WHERE type='cve' AND id NOT LIKE 'cve-CVE-%'"),
    ]
    all_ok = True
    details = []
    for name, sql in checks:
        v = db.execute(sql).fetchone()[0]
        ok = v == 0
        if not ok:
            all_ok = False
        details.append((ok, name, v))
    return all_ok, details


def panel(db):
    """§一.5 数据面板。"""
    total = db.execute("SELECT count(*) FROM records").fetchone()[0]
    enriched = db.execute("SELECT count(*) FROM records WHERE status='enriched' AND length(content_md)>=300").fetchone()[0]
    art = db.execute("SELECT count(*) FROM records WHERE type IN ('article','rss_article') AND status='enriched'").fetchone()[0]
    ai_cve = db.execute("SELECT count(*) FROM vuln_meta WHERE ai_related=1").fetchone()[0]
    no_body = db.execute("SELECT count(*) FROM records WHERE status='no_body'").fetchone()[0]
    failed = db.execute("SELECT count(*) FROM records WHERE status='detail_failed'").fetchone()[0]
    print(f"\n  面板: 总{total} | enriched {enriched} | 文章全文 {art} | AI CVE {ai_cve} | no_body {no_body} | failed {failed}")


def sample(db, n):
    """§二 抽样：随机取 n 条最新 enriched 记录供人工审读。"""
    rows = db.execute("""SELECT source, title, url, substr(content_md,1,80), publish_time
        FROM records WHERE status='enriched' AND type IN ('article','rss_article')
        ORDER BY Random() LIMIT ?""", (n,)).fetchall()
    print(f"\n== 抽样 {len(rows)} 条（逐条核对：标题/正文开头/日期/URL 可打开）==")
    for src, t, url, md, pt in rows:
        print(f"\n  [{src[:20]}] {t[:40]}")
        print(f"    日期: {pt} | {url[:70]}")
        print(f"    正文开头: {md[:70]}…")


def vector_ready(db):
    """§四 向量化前专项。"""
    checks = [
        ("文章全文量>1000", "SELECT count(*) FROM records WHERE type IN ('article','rss_article') AND status='enriched' AND length(content_md)>=300", lambda v: v > 1000),
        ("全文拦截页0", "SELECT count(*) FROM records WHERE status='enriched' AND source NOT IN ('xianzhi','secrss') AND (content_md LIKE '%请按住滑块%' OR content_md LIKE '%环境异常%')", lambda v: v == 0),
        ("CVE域content完整", "SELECT count(*) FROM records r JOIN vuln_meta m ON r.id='cve-'||m.cve_id WHERE m.ai_related=1 AND length(r.content_md)<50", lambda v: v < 50),
        ("md导出一致", "SELECT abs((SELECT count(*) FROM records WHERE status='enriched' AND length(content_md)>=300) - (SELECT count(*) FROM records WHERE status='enriched' AND length(content_md)>=300))", lambda v: v < 100),
    ]
    print("\n== 向量化前专项 ==")
    for name, sql, judge in checks:
        v = db.execute(sql).fetchone()[0]
        print(f"  {'✓' if judge(v) else '✗'} {name}: {v}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--vector-ready", action="store_true")
    args = ap.parse_args()

    p = Path(DB)
    if not p.exists():
        print(f"[error] {DB} 不存在")
        sys.exit(1)
    db = sqlite3.connect(p)

    print("== 例行核查 ==")
    all_ok, details = check_routine(db)
    for ok, name, v in details:
        print(f"  {'✓' if ok else '✗ 异常!'} {name}: {v}")
    panel(db)

    if args.sample:
        sample(db, args.sample)
    if args.vector_ready:
        vector_ready(db)

    # 心跳检查
    hb = Path("data/heartbeat.json")
    if hb.exists():
        import json
        h = json.loads(hb.read_text())
        age_h = (datetime.now() - datetime.fromisoformat(h["last_run"])).total_seconds() / 3600
        print(f"\n  心跳: {h['last_run']} ({age_h:.0f}h 前, {'✓' if age_h < 26 else '✗ 过期'})")
    else:
        print("\n  心跳: 不存在（run_daily 未跑过）")

    print(f"\n结论: {'全绿 ✓' if all_ok else '存在异常，按规范 §一 处置 ❌'}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()

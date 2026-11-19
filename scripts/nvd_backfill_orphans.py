#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvd_backfill_orphans.py —— 给 vuln_meta 里的"孤儿 CVE"按 ID 补拉 NVD 描述入库

背景：vuln_meta 里有 433 条 weak AI 信号 CVE 只有结构化标签（cvss/epss/cpes），
     没有 records 正文行（多源合并时只写了标签表）。LLM 复核需要标题/描述才能
     裁决。本脚本按 cve_id 逐个调 NVD API 2.0 补建 records 行；补完后
     llm_review_weak.py 的 JOIN 自动覆盖它们。

用法：
    uv run python scripts/nvd_backfill_orphans.py --dry-run        # 看要补多少条
    uv run python scripts/nvd_backfill_orphans.py --limit 5        # 试跑5条
    uv run python scripts/nvd_backfill_orphans.py                  # 全量（断点续传）
凭据：.env 的 NVD_API_KEY 可选——无 key 5次/30秒（约47分钟），有 key 50次/30秒。
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from xianzhi_crawler import Store, now_iso

ROOT = Path(__file__).resolve().parent.parent


def load_dotenv() -> dict:
    env = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="./data")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0, help="请求间隔秒，默认按有无key自动取")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    store = Store(Path(args.out_dir))
    orphans = [r[0] for r in store.db.execute("""
        SELECT cve_id FROM vuln_meta v
        WHERE v.ai_signal='weak' AND v.llm_ai_related IS NULL
          AND v.cve_id LIKE 'CVE-%'
          AND NOT EXISTS(SELECT 1 FROM records r WHERE r.id = 'cve-' || v.cve_id)
        ORDER BY cve_id""").fetchall()]
    if args.limit:
        orphans = orphans[:args.limit]
    key = load_dotenv().get("NVD_API_KEY", "")
    sleep = args.sleep or (1.0 if key else 6.5)
    print(f"孤儿 CVE 待补：{len(orphans)} 条（key={'有' if key else '无'}，间隔 {sleep}s）")
    if args.dry_run:
        for c in orphans[:5]:
            print("  例:", c)
        return

    state_p = Path(args.out_dir) / "state_nvd_orphans.json"
    done = set(json.loads(state_p.read_text())["done"]) if state_p.exists() else set()
    ok = miss = 0
    sess = requests.Session()
    if key:   # 空 key 也发 apiKey 头会被 NVD 拒（非 JSON 错误体）——2026-10-03 修复
        sess.headers["apiKey"] = key
    for i, cid in enumerate(orphans, 1):
        if cid in done:
            continue
        try:
            r = sess.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         params={"cveId": cid}, timeout=args.timeout)
            if r.status_code in (403, 429):          # 限流：退避后重试一次
                time.sleep(15)
                r = sess.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"cveId": cid}, timeout=args.timeout)
            items = r.json().get("vulnerabilities", [])
        except (requests.RequestException, ValueError) as e:
            print(f"  [{cid}] {type(e).__name__}，跳过待重跑")
            continue
        if not items:
            miss += 1                                 # Reserved 等：NVD 也没有描述
            done.add(cid)
        else:
            cj = items[0]["cve"]
            desc = next((d["value"] for d in cj["descriptions"] if d["lang"] == "en"), "")
            score = ((cj.get("metrics", {}).get("cvssMetricV31") or
                      cj.get("metrics", {}).get("cvssMetricV30") or [{}])[0]
                     .get("cvssData", {}).get("baseScore"))
            severity = ((cj.get("metrics", {}).get("cvssMetricV31") or
                         cj.get("metrics", {}).get("cvssMetricV30") or [{}])[0]
                        .get("cvssData", {}).get("baseSeverity", ""))
            rec = {"id": "cve-" + cid, "source": "nvd", "type": "cve",
                   "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                   "title": f"{cid}{' [' + severity + ']' if severity else ''}: {desc[:90]}",
                   "summary": desc[:1200], "publish_time": (cj.get("published") or "")[:16].replace("T", " "),
                   "tags": ["cve", "nvd"] + ([f"CVSS:{severity}"] if severity else []),
                   "crawl_time": now_iso(), "content_md": desc}
            if not store.seen(rec["url"]):
                store.upsert(rec, "listed")
            done.add(cid)
            ok += 1
        state_p.write_text(json.dumps({"done": sorted(done)}))
        if i % 20 == 0:
            print(f"  进度 {i}/{len(orphans)}  成功 {ok} 无描述 {miss}")
        time.sleep(sleep)
    store.flush()
    print(f"完成：补正文 {ok}，NVD 无描述 {miss}（维持规则判定）")


if __name__ == "__main__":
    main()

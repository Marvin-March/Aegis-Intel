#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nvd_recover_external.py —— 回收"文章引用了但库中没有"的库外 CVE（编造检测副产物）

背景：enrich_llm 的编造检测（fabricate_check）累计标记 295 处 / 225 个独立 CVE 编号，
     抽 4 个送 NVD 验证全部真实存在（Dify SSRF、RAGFlow、EchoLeak 等）——即 LLM 提取
     准确，编号只是"文章提到但本库未采集"。这批编号是文章投票选出的高价值采集线索。
做法：从 article_enrich.entities.cves 汇总全部编号（CVE 正则过滤脏值，如字面 "NULL"），
     与库内 diff 出缺口，逐个按 ID 调 NVD 2.0 补拉描述，写入 records（走 Store.upsert
     质量门）+ vuln_meta（ai_signal='weak'，ai_related=0），交给 llm_review_weak 的
     三级裁决自然分流——判进 AI 库的会被 enrich_llm 富化，与主链路完全复用。

用法：
    uv run python scripts/nvd_recover_external.py --dry-run    # 只看缺口清单
    uv run python scripts/nvd_recover_external.py --limit 5    # 试跑 5 条
    uv run python scripts/nvd_recover_external.py              # 全量（断点续传）
凭据：.env 的 NVD_API_KEY 可选——无 key 5次/30秒（约6.5s/条），有 key 50次/30秒。
"""

import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from xianzhi_crawler import Store, now_iso

ROOT = Path(__file__).resolve().parent.parent
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def db_write(store, fn, tries: int = 6):
    """带锁重试的幂等写入（同库并发写手的 BUSY 不被 busy_handler 重试，自行循环——
    与 enrich_l1 的重试环同一套路；写入均幂等，重放零风险）。"""
    for t in range(tries):
        try:
            fn()
            store.flush()
            return
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) or t == tries - 1:
                raise
            time.sleep(2 * (t + 1))


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


def collect_external(db) -> dict:
    """汇总文章富化实体里的 CVE 编号 → {cve_id: 票数}，剔掉库内已有的。"""
    votes: dict[str, int] = {}
    for (entities,) in db.execute("SELECT entities FROM article_enrich WHERE entities IS NOT NULL"):
        try:
            cves = json.loads(entities).get("cves", [])
        except (ValueError, TypeError):
            continue
        for c in cves:
            c = str(c).strip().upper()
            if CVE_RE.match(c):          # 脏值（如字面 "NULL"）在这里被拦下
                votes[c] = votes.get(c, 0) + 1
    known = {r[0] for r in db.execute("SELECT cve_id FROM vuln_meta WHERE cve_id LIKE 'CVE-%'")}
    return {c: n for c, n in sorted(votes.items(), key=lambda x: -x[1]) if c not in known}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="./data")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0, help="请求间隔秒，默认按有无key自动取")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    store = Store(Path(args.out_dir))
    ext = collect_external(store.db)
    if args.limit:
        ext = dict(list(ext.items())[:args.limit])
    key = load_dotenv().get("NVD_API_KEY", "")
    sleep = args.sleep or (1.0 if key else 6.5)
    print(f"库外 CVE 缺口：{len(ext)} 个（按文章引用票数排序；key={'有' if key else '无'}，间隔 {sleep}s）")
    if args.dry_run:
        for c, n in list(ext.items())[:15]:
            print(f"  {c}  被引 {n} 次")
        return

    state_p = Path(args.out_dir) / "state_nvd_external.json"
    done = set(json.loads(state_p.read_text())["done"]) if state_p.exists() else set()
    ok = miss = 0
    sess = requests.Session()
    if key:   # 空 apiKey 头会被 NVD 拒（2026-10-03 修复的同款坑）
        sess.headers["apiKey"] = key
    for i, (cid, votes) in enumerate(ext.items(), 1):
        if cid in done:
            continue
        try:
            r = sess.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         params={"cveId": cid}, timeout=args.timeout)
            if r.status_code in (403, 429):
                time.sleep(15)
                r = sess.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                             params={"cveId": cid}, timeout=args.timeout)
            items = r.json().get("vulnerabilities", [])
        except (requests.RequestException, ValueError) as e:
            print(f"  [{cid}] {type(e).__name__}，跳过待重跑")
            continue
        if not items:
            miss += 1                                 # 编号无效 / NVD 未收录：记 done 不再试
            done.add(cid)
        else:
            cj = items[0]["cve"]
            desc = next((d["value"] for d in cj["descriptions"] if d["lang"] == "en"), "")
            m = ((cj.get("metrics", {}).get("cvssMetricV31") or
                  cj.get("metrics", {}).get("cvssMetricV30") or [{}])[0].get("cvssData", {}))
            severity, score = m.get("baseSeverity", ""), m.get("baseScore")
            cpes = json.dumps([c["criteria"] for w in cj.get("configurations", [])
                               for n in w.get("nodes", []) for c in n.get("cpeMatch", [])],
                              ensure_ascii=False)
            rec = {"id": "cve-" + cid, "source": "nvd", "type": "cve",
                   "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                   "title": f"{cid}{' [' + severity + ']' if severity else ''}: {desc[:90]}",
                   "summary": desc[:1200], "publish_time": (cj.get("published") or "")[:16].replace("T", " "),
                   "tags": ["cve", "nvd", f"article_vote:{votes}"] + ([f"CVSS:{severity}"] if severity else []),
                   "crawl_time": now_iso(), "content_md": desc}
            if not store.seen(rec["url"]):
                store.upsert(rec, "listed")
            store.db.execute("""INSERT OR IGNORE INTO vuln_meta
                (cve_id,cvss,severity,cpes,ai_related,matched,ai_signal,updated_at)
                VALUES(?,?,?,?,0,?,'weak',?)""",
                (cid, score, severity, cpes, f"article_vote:{votes}", now_iso()))
            done.add(cid)
            ok += 1
        store.flush()
        state_p.write_text(json.dumps({"done": sorted(done)}))
        if i % 20 == 0:
            print(f"  进度 {i}/{len(ext)}  入库 {ok}  NVD 无此编号 {miss}")
        time.sleep(sleep)
    store.flush()
    print(f"完成：回收入库 {ok} 条（ai_signal='weak'，待 llm_review_weak 裁决），NVD 无此编号 {miss}")


if __name__ == "__main__":
    main()

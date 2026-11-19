#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enrich_l1.py —— 富化管线 L1：确定性富化（纯脚本，零 LLM 成本，幂等可重跑）

面向"情报富化：定位受影响资产与组件、关联技术论文与分析文章"：
  1. CPE 解析           → vuln_meta.affected_component（AI 库行）
  2. GHA 公告解析        → affected_versions + affected_component 补充（免费版本区间）
  3. 包名命中回收        → llm_review 的"包名命中:X"理由 → affected_component
  4. 文章正则抽 CVE      → 新表 article_cve（"关联分析文章"的关联表）
  5. 论文×组件词边界匹配  → 新表 paper_link（"关联技术论文"的关联表）

L3 的 LLM 语义富化（摘要/攻击类型/修复建议）见 enrich_llm.py，不在此文件。
用法：uv run python scripts/enrich_l1.py [--out-dir ./data] [--dry-run]
"""

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from llm_review_weak import AI_PKG_RE          # 38+ 个 AI 包名的词边界正则（单一事实源）
from xianzhi_crawler import now_iso

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
RANGE_RE = re.compile(   # 版本区间：">= 0.1.0, < 0.3.5" / "<0.3.5" / "1.x.y 之前" 等
    r"(?:>=|<=|<|>|==)\s*v?\d+(?:\.\d+)*(?:\s*,\s*(?:<=|<)\s*v?\d+(?:\.\d+)+)?"
    r"|before\s+v?\d+(?:\.\d+)+|prior\s+to\s+v?\d+(?:\.\d+)+", re.I)


def cpe_products(cpes_json: str) -> list:
    """cpe:2.3:a:vendor:product:... → 取 product（'*' 跳过），去重保序。"""
    out = []
    try:
        for c in json.loads(cpes_json or "[]"):
            parts = str(c).split(":")
            if len(parts) >= 5:
                prod = parts[4] if parts[4] != "*" else (parts[3] if len(parts) > 3 and parts[3] != "*" else "")
                if prod and prod not in out:
                    out.append(prod)
    except ValueError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="./data")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    db = sqlite3.connect(Path(args.out_dir) / "index.sqlite")
    db.execute("PRAGMA busy_timeout=30000")   # 富化批处理持写锁时多等一会（30s）
    stats = {"cpe_component": 0, "reason_component": 0, "gha_versions": 0,
             "article_cve": 0, "article_hit": 0, "paper_link": 0}

    # ── 表结构准备（幂等）─────────────────────────────────────────
    cols = {r[1] for r in db.execute("PRAGMA table_info(vuln_meta)").fetchall()}
    for col in ("affected_component", "affected_versions"):
        if col not in cols:
            db.execute(f"ALTER TABLE vuln_meta ADD COLUMN {col} TEXT DEFAULT ''")
    db.execute("""CREATE TABLE IF NOT EXISTS article_cve(
        article_url TEXT, cve_id TEXT, created_at TEXT,
        PRIMARY KEY(article_url, cve_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS paper_link(
        paper_url TEXT, component TEXT, created_at TEXT,
        PRIMARY KEY(paper_url, component))""")
    db.commit()

    # ── 1. CPE 解析 → affected_component（仅 AI 库行）────────────────
    rows = db.execute("""SELECT cve_id, cpes FROM vuln_meta
        WHERE ai_related=1 AND cpes != '' AND cpes != '[]'
        AND (affected_component IS NULL OR affected_component='')""").fetchall()
    updates = []
    for cid, cpes in rows:
        prods = cpe_products(cpes)
        if prods:
            updates.append((",".join(prods[:5]), cid))
    if not args.dry_run and updates:
        db.executemany("UPDATE vuln_meta SET affected_component=? WHERE cve_id=?", updates)
    stats["cpe_component"] = len(updates)

    # ── 2. 包名命中回收（llm_review 的裁决理由 → affected_component）────
    rows = db.execute("""SELECT cve_id, llm_reason FROM vuln_meta
        WHERE llm_reason LIKE '包名命中:%'
        AND (affected_component IS NULL OR affected_component='')""").fetchall()
    updates = [(r[1].split(":", 1)[1].strip(), r[0]) for r in rows if ":" in r[1]]
    if not args.dry_run and updates:
        db.executemany("UPDATE vuln_meta SET affected_component=? WHERE cve_id=?", updates)
    stats["reason_component"] = len(updates)

    # ── 3. GHA 公告 → affected_versions + 组件补充（按 CVE 号对齐）──────
    gha = db.execute("""SELECT id, title, content_md FROM records
        WHERE source='github_advisory' AND id LIKE 'cve-CVE-%'""").fetchall()
    updates_v, updates_c = [], []
    for rid, title, content in gha:
        cid = rid.replace("cve-", "", 1)
        ranges = sorted(set(m.group(0).replace(" ", "") for m in RANGE_RE.finditer(content or "")))
        comp = title.split(":", 1)[1].split(":", 1)[0].strip() if ":" in title else ""
        if ranges:
            updates_v.append((";".join(ranges[:6]), cid))
        if comp:
            updates_c.append((comp[:60], cid))
    if not args.dry_run:
        db.executemany("""UPDATE vuln_meta SET affected_versions=?
            WHERE cve_id=? AND (affected_versions IS NULL OR affected_versions='')""",
            [u for u in updates_v if u[1]])   # 无对应 vuln_meta 行的 UPDATE 静默 0 行，无害
        db.executemany("""UPDATE vuln_meta SET affected_component=?
            WHERE cve_id=? AND (affected_component IS NULL OR affected_component='')""", updates_c)
    stats["gha_versions"] = len(updates_v)

    # ── 4. 文章正则抽 CVE → article_cve ─────────────────────────────
    arts = db.execute("""SELECT url, title, summary, content_md FROM records
        WHERE type IN ('article','rss_article') AND length(content_md)>=300""").fetchall()
    links = []
    for url, title, summary, md in arts:
        ids = set(CVE_RE.findall(f"{title} {summary or ''} {md or ''}"))
        if ids:
            stats["article_hit"] += 1
            links += [(url, c, now_iso()) for c in sorted(ids)]
    if not args.dry_run and links:
        db.executemany("INSERT OR IGNORE INTO article_cve VALUES(?,?,?)", links)
    stats["article_cve"] = len(links)

    # ── 5. 论文 × 组件 → paper_link ─────────────────────────────────
    papers = db.execute("""SELECT url, title, summary FROM records
        WHERE type='paper'""").fetchall()
    plinks = []
    for url, title, summary in papers:
        comps = sorted(set(m.group(0).lower() for m in AI_PKG_RE.finditer(f"{title} {summary or ''}")))
        if comps:
            plinks += [(url, c, now_iso()) for c in comps]
    if not args.dry_run and plinks:
        db.executemany("INSERT OR IGNORE INTO paper_link VALUES(?,?,?)", plinks)
    stats["paper_link"] = len(plinks)

    # ── 6. 零信号池补扫（2026-10-03 新增：实测漏报 112 条，含 Flowise CRITICAL、
    #     MCP 服务器家族——它们不在原始 31 包监控清单且描述不带 AI 字样）──────
    #    命中即回捞：ai_related=1 + llm_ai_related=1（跳过 LLM 复核，包名即证据）+
    #    ai_signal='weak'（语义一致：词匹配命中）+ llm_reason 留痕；Rejected（NVD 撤销）除外
    zero = db.execute("""SELECT v.cve_id, r.title, r.summary FROM vuln_meta v
        JOIN records r ON r.id='cve-'||v.cve_id
        WHERE v.ai_related=0 AND (v.ai_signal='' OR v.ai_signal='none')""").fetchall()
    rescued = []
    for cid, title, summary in zero:
        if "Rejected" in (title or ""):
            continue
        m = sorted(set(x.group(0).lower() for x in AI_PKG_RE.finditer(f"{title} {summary or ''}")))
        if m:
            rescued.append(("包名命中:" + ",".join(m[:3]), cid))
    if not args.dry_run and rescued:
        db.executemany("""UPDATE vuln_meta SET ai_related=1, llm_ai_related=1,
            llm_reason=?, ai_signal='weak' WHERE cve_id=?""", rescued)
    stats["rescued"] = len(rescued)

    if args.dry_run:
        db.rollback()
        print("[dry-run]", stats)
    else:
        db.commit()
        print("L1 完成：", stats)
        print("article_cve 行数:", db.execute("SELECT COUNT(*) FROM article_cve").fetchone()[0])
        print("paper_link 行数:", db.execute("SELECT COUNT(*) FROM paper_link").fetchone()[0])
        print("AI 库有 affected_component:",
              db.execute("SELECT COUNT(*) FROM vuln_meta WHERE ai_related=1 AND affected_component!=''").fetchone()[0],
              "/ 1233")
        print("AI 库有 affected_versions:",
              db.execute("SELECT COUNT(*) FROM vuln_meta WHERE ai_related=1 AND affected_versions!=''").fetchone()[0])


if __name__ == "__main__":
    main()

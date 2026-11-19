#!/usr/bin/env python3
"""全量语料预处理：data/index.sqlite（唯一事实源）+ data/daily/*.md → data/chunks.jsonl。

覆盖范围（2026-10-06 与委托人确认：data/ 下的知识语料全部入库）：
- records 表：content_md 或 summary 非空的全部记录（cve/advisory/article/rss_article/paper）
- daily/：每日资讯摘要（domain=daily）

不入库（非语料）：export_backup_20261006（export 的原件备份，内容重复）、runs/（采集运行日志）、
raw/（空）、state_nvd_orphans.json 与 xianzhi_records.jsonl（爬虫状态文件，内容已在 records）。
export/ 目录是本脚本产出的子集的人类可读版，不再作为数据源。

块规则（与 preprocess_export.py 一致）：
- cve/advisory：标题+中文摘要(vuln_meta)+正文+组件 拼装，>2000 字切块
- article/rss_article：~700 字切块 overlap 100，锚定头 "{标题} | {来源} | {日期}"
- paper：标题+摘要 单块（>2000 字才切）
- daily：整文按文章切块
- id = sha1(f"{record_id}#{chunk_index}")，幂等

用法: python scripts/preprocess_corpus.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

from preprocess_export import CHUNK_TARGET, CHUNK_OVERLAP, CVE_RE, clean_body, chunk_text

ROOT = Path(__file__).resolve().parent.parent
INDEX_DB = ROOT / "data" / "index.sqlite"
DAILY_DIR = ROOT / "data" / "daily"
CHUNKS_JSONL = ROOT / "data" / "chunks.jsonl"
CORPUS_META_JSONL = ROOT / "data" / "corpus_meta.jsonl"

DOMAIN_BY_TYPE = {
    "cve": "cve",
    "advisory": "cve",
    "article": "article",
    "rss_article": "article",
    "paper": "paper",
}


def load_vuln_meta() -> dict[str, dict]:
    con = sqlite3.connect(f"file:{INDEX_DB.as_posix()}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT cve_id, ai_related, summary_zh, affected_component FROM vuln_meta"
    ).fetchall()
    con.close()
    return {r[0]: {"ai_related": r[1], "summary_zh": r[2] or "", "component": r[3] or ""}
            for r in rows}


def iter_records() -> list[dict]:
    con = sqlite3.connect(f"file:{INDEX_DB.as_posix()}?mode=ro", uri=True)
    rows = con.execute(
        "SELECT id, source, type, url, title, publish_time, content_md, summary "
        "FROM records"
    ).fetchall()
    con.close()
    out = []
    for rid, source, rtype, url, title, pub, content_md, summary in rows:
        body = (content_md or "").strip()
        if not body:
            summary = (summary or "").strip()
            if not summary:
                continue  # 无正文无摘要的爬取残片
            body = summary  # 论文等：摘要在 summary 字段
        out.append({
            "record_id": rid, "source": source or "", "type": rtype or "",
            "url": url or "", "title": (title or "").strip(), "publish_time": pub or "",
            "body": body,
        })
    return out


def build_record_chunks(rec: dict, vuln_meta: dict) -> tuple[list[str], dict]:
    """返回 (该记录的所有块文本, 额外元数据)。"""
    domain = DOMAIN_BY_TYPE.get(rec["type"], "article")
    title = rec["title"] or rec["record_id"]
    body = clean_body(rec["body"])
    cve_ids = sorted(set(CVE_RE.findall(f"{title}\n{body}")))[:10]
    vm = vuln_meta.get(cve_ids[0], {}) if cve_ids else {}

    if domain == "cve":
        parts = [title]
        if vm.get("summary_zh"):
            parts.append("中文摘要: " + vm["summary_zh"])
        parts.append(body)
        if vm.get("component"):
            parts.append(f"组件: {vm['component']}")
        assembled = "\n".join(parts)
        if len(assembled) > 2000:
            pieces = chunk_text(assembled)
            texts = [f"{title} ({i+1}/{len(pieces)})\n{c}" for i, c in enumerate(pieces)]
        else:
            texts = [assembled]
    elif domain == "paper":
        assembled = f"{title}\n{body}"
        if len(assembled) > 2000:
            pieces = chunk_text(assembled)
            texts = [f"{title} ({i+1}/{len(pieces)})\n{c}" for i, c in enumerate(pieces)]
        else:
            texts = [assembled]
    else:
        anchor = f"{title} | {rec['source']} | {rec['publish_time'][:10]}\n"
        texts = [anchor + c for c in chunk_text(body)]

    meta = {"domain": domain, "cve_ids": ",".join(cve_ids),
            "ai_related": int(bool(vm.get("ai_related")))}
    return texts, meta


def main() -> int:
    t0 = time.time()
    vuln_meta = load_vuln_meta()
    records = iter_records()
    print(f"[init] records 有正文/摘要: {len(records)} 条 | vuln_meta {len(vuln_meta)} 条")

    daily_files = sorted(DAILY_DIR.glob("*.md")) if DAILY_DIR.exists() else []
    print(f"[init] daily 摘要: {len(daily_files)} 份")

    meta_out = CORPUS_META_JSONL.open("w", encoding="utf-8")
    chunk_out = CHUNKS_JSONL.open("w", encoding="utf-8")
    stat: Counter = Counter()
    skipped_type: Counter = Counter()
    n_chunks_total = 0

    def emit(rid: str, source: str, url: str, title: str, publish_time: str,
             texts: list[str], meta: dict) -> None:
        nonlocal n_chunks_total
        n = len(texts)
        for i, chunk in enumerate(texts):
            rec_out = {
                "id": hashlib.sha1(f"{rid}#{i}".encode()).hexdigest(),
                "record_id": rid, "domain": meta["domain"], "source": source,
                "url": url, "title": title[:300], "publish_time": publish_time,
                "chunk_index": i, "n_chunks": n,
                "cve_ids": meta["cve_ids"], "ai_related": meta["ai_related"],
                "text": chunk,
            }
            chunk_out.write(json.dumps(rec_out, ensure_ascii=False) + "\n")
        meta_out.write(json.dumps({
            "record_id": rid, "domain": meta["domain"], "source": source, "url": url,
            "title": title, "publish_time": publish_time, "n_chunks": n,
        }, ensure_ascii=False) + "\n")
        stat[meta["domain"]] += 1
        n_chunks_total += n

    for rec in records:
        domain = DOMAIN_BY_TYPE.get(rec["type"])
        if domain is None:
            skipped_type[rec["type"] or "(空)"] += 1
            continue
        texts, meta = build_record_chunks(rec, vuln_meta)
        emit(rec["record_id"], rec["source"], rec["url"], rec["title"],
             rec["publish_time"], texts, meta)

    for path in daily_files:
        text = clean_body(path.read_text(encoding="utf-8", errors="replace"))
        date = path.stem
        anchor = f"每日AI安全资讯 {date} | daily\n"
        texts = [anchor + c for c in chunk_text(text)]
        emit(f"daily-{date}", "daily", "", f"每日 AI 安全资讯（{date}）", date,
             texts, {"domain": "daily", "cve_ids": "", "ai_related": 0})

    meta_out.close()
    chunk_out.close()

    lens = [len(json.loads(l)["text"]) for l in open(CHUNKS_JSONL, encoding="utf-8")]
    print(f"\n[done] 记录 {stat.total()} 条(跳过未知type {sum(skipped_type.values())}: "
          f"{dict(skipped_type)}) | 出块 {n_chunks_total}")
    print(f"块长: min {min(lens)} / avg {sum(lens)//len(lens)} / max {max(lens)}")
    print(f"域分布: {dict(stat)}")
    print(f"产物: {CHUNKS_JSONL.name}({CHUNKS_JSONL.stat().st_size//2**20}MB), "
          f"{CORPUS_META_JSONL.name}({CORPUS_META_JSONL.stat().st_size//1024}KB), "
          f"耗时 {(time.time()-t0)/60:.1f}min")
    return 0


if __name__ == "__main__":
    sys.exit(main())

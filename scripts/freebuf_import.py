#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
freebuf_import.py —— 导入队友 FreeBufAICrawler 采集成果（973 篇元数据 + 已转 md 的正文）

处理"其他社区没有深抓文章"的缺口：FreeBuf 是第二个深抓社区（队友爬虫产出），
本脚本把它合入统一库：元数据全量、正文取 ai_md/<id>.md（剥 YAML front-matter）、
付费文章只留元数据（status=no_body + 付费标签）、原始 md 归档到 data/raw/freebuf/。

用法：uv run python scripts/freebuf_import.py [--src D:\\liuduo\\qq\\FreebufAICrawler_1.0.0] [--out-dir ./data]
"""

import argparse
import json
import shutil
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent))
from xianzhi_crawler import Store, now_iso


def strip_front_matter(md: str) -> str:
    parts = md.split("---", 2)
    return parts[2].strip() if len(parts) == 3 else md.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=r"./external/FreebufAICrawler_1.0.0")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()
    src = Path(args.src)
    meta_file = src / "ai_articles.json"
    if not meta_file.exists():
        print(f"[error] 找不到 {meta_file}")
        return
    articles = json.loads(meta_file.read_text(encoding="utf-8"))
    md_dir = src / "ai_md"

    store = Store(Path(args.out_dir))
    raw_dir = Path(args.out_dir) / "raw" / "freebuf"
    raw_dir.mkdir(parents=True, exist_ok=True)

    n_new = n_full = n_paid = n_backfill = 0
    for a in articles:
        url = a.get("url", "")
        if not url:
            continue
        paid = bool(a.get("vip_read"))
        md_path = md_dir / f"{a['id']}.md"
        content_md = ""
        if md_path.exists():
            content_md = strip_front_matter(md_path.read_text(encoding="utf-8"))
            shutil.copy2(md_path, raw_dir / f"{a['id']}.md")   # 源头归档

        if store.seen(url):
            # 已有记录（如污染清洗后 no_body）→ 用队友爬虫的 md 回填正文
            if content_md and len(content_md) >= 300:
                cur = store.db.execute("SELECT status, length(content_md) FROM records WHERE url=?", (url,)).fetchone()
                if cur and (cur[0] != "enriched" or cur[1] < 300):
                    store.db.execute("UPDATE records SET content_md=?, status='enriched', crawl_time=? WHERE url=?",
                                     (content_md, now_iso(), url))
                    n_backfill += 1
            continue

        rec = {
            "id": f"freebuf-{a['id']}",
            "source": "freebuf",
            "type": "rss_article",
            "url": url,
            "title": a.get("title", ""),
            "summary": (a.get("summary") or "")[:500],
            "publish_time": (a.get("date") or "")[:16],
            "tags": ["freebuf", a.get("category", ""), "付费" if paid else "",
                     f"作者:{a.get('author', '')}"] if a.get("author") else ["freebuf", a.get("category", "")],
            "crawl_time": now_iso(),
            "content_md": content_md,
        }
        rec["tags"] = [t for t in rec["tags"] if t]
        if paid:
            status = "no_body"                      # 付费：只留元数据（合规）
        elif len(content_md) >= 300:
            status = "enriched"
        elif content_md:
            status = "low_content"
        else:
            status = "listed"                       # 待转换/待 deep_fill
        store.upsert(rec, status)
        n_new += 1
        if status == "enriched":
            n_full += 1
        if paid:
            n_paid += 1
    store.db.commit()
    print(f"[freebuf] 新增 {n_new} 条（全文 {n_full}，付费 {n_paid}），回填正文 {n_backfill} 条")
    print("raw 归档:", raw_dir)


if __name__ == "__main__":
    main()

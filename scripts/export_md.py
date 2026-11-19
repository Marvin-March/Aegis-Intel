#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_md.py —— 按源导出全文文章为 Markdown 文件

用途：① Dify/RAGFlow 知识库批量上传  ② 交付展示  ③ 人工审阅
每篇一个 .md，带 YAML front-matter（title/source/url/publish_time），
输出到 data/export/<源名>/。只导出有正文的（≥300 字），跳过 no_body/low_content。

用法：uv run python scripts/export_md.py [--source freebuf] [--out-dir ./data]
"""

import argparse
import json
import re
from pathlib import Path

import sqlite3


def slug(url: str) -> str:
    # 2026-10-03 修复文件互相覆盖：CVE 链接第一段 4 位数字是年份，2.2 万条记录
    # 全在抢 "2026.md" 这类名字，hash%9999 后缀生日碰撞导致静默覆盖丢文件。
    # 现在：CVE 链接直接用 CVE 编号；其余 URL 保留数字 id + 12 位哈希后缀保证唯一。
    m = re.search(r"CVE-\d{4}-\d{4,7}", url)
    if m:
        return m.group(0)
    m = re.search(r"(\d{4,})", url)
    import hashlib
    head = m.group(1) if m else ""
    return (head + "-" if head else "") + hashlib.sha1(url.encode()).hexdigest()[:12]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="", help="只导指定源（freebuf/xianzhi/anquanke…，空=全部有正文的）")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    db = sqlite3.connect(Path(args.out_dir) / "index.sqlite")
    cond = "length(r.content_md)>=300"
    if args.source:
        cond += f" AND (r.source='{args.source}' OR r.url LIKE '%{args.source}%')"
    # 富化字段（2026-10-03）：summary_zh 进 front-matter——中文摘要让 Dify 等知识库
    # 的中文提问能直接命中英文文档，是富化价值接进问答链路的最后一米
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    join = ""
    if "article_enrich" in tables:
        join += " LEFT JOIN article_enrich ae ON ae.url = r.url"
    if "vuln_meta" in tables:
        join += " LEFT JOIN vuln_meta vm ON r.id LIKE 'cve-%' AND vm.cve_id = substr(r.id, 5)"
    sz_expr = ("COALESCE(NULLIF(ae.summary_zh,''), NULLIF(vm.summary_zh,''), '')"
               if join else "''")
    comp_expr = ("COALESCE(NULLIF(vm.affected_component,''), '')"
                 if "vuln_meta" in tables else "''")
    rows = db.execute(f"""SELECT r.url, r.title, r.content_md, r.source, r.publish_time,
                          {sz_expr}, {comp_expr} FROM records r{join}
                          WHERE {cond} ORDER BY r.source, r.publish_time DESC""").fetchall()

    out_root = Path(args.out_dir) / "export"
    n, seen = 0, set()
    for url, title, md, source, pt, sz, comp in rows:
        src_dir = out_root / re.sub(r"[^\w-]", "_", source)
        src_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{slug(url)}.md"
        rel = str(src_dir / fname)
        if rel in seen:   # 同目录撞名（极罕见）：追加长哈希
            import hashlib
            fname = f"{Path(fname).stem}_{hashlib.sha1(url.encode()).hexdigest()[:16]}.md"
            rel = str(src_dir / fname)
        seen.add(rel)
        extra = ""
        if sz:
            extra += f"summary_zh: {json.dumps(sz, ensure_ascii=False)}\n"
        if comp:
            extra += f"affected_component: {comp}\n"
        front = (f"---\ntitle: {json.dumps(title, ensure_ascii=False)}\nsource: {source}\nurl: {url}\n"
                 f"publish_time: \"{pt}\"\n{extra}---\n\n")
        (src_dir / fname).write_text(front + md, encoding="utf-8")
        n += 1
    print(f"[export] 导出 {n} 个 md → {out_root}")


if __name__ == "__main__":
    main()

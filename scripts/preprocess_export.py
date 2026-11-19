#!/usr/bin/env python3
"""data/export 预处理：原文清洗（原地）+ 向量化就绪块（data/chunks.jsonl）。

处理内容（对应 2026-10-06 结论的四步）：
1. 剥 frontmatter → 元数据存 data/export_meta.jsonl（原文只留正文）
2. 清噪：去 markdown 图片链接、链接只留文字、压缩 3+ 空行
3. CVE 文件去重 "- Ref:" 重复行
4. 切块 → data/chunks.jsonl：CVE 整条拼装（标题+中文摘要+正文+组件），
   文章 ~700 字切块 overlap 100，每块锚定头 "{标题} | {来源} | {日期}"

幂等：清洗后文件没有 frontmatter 时，元数据从 export_meta.jsonl 回读，可重复执行。
备份：运行前需自行确认 data/export_backup_20261006/ 存在（本脚本不负责备份）。

用法: python scripts/preprocess_export.py [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPORT_DIR = ROOT / "data" / "export"
META_JSONL = ROOT / "data" / "export_meta.jsonl"
CHUNKS_JSONL = ROOT / "data" / "chunks.jsonl"
INDEX_DB = ROOT / "data" / "index.sqlite"

CVE_SOURCES = {"nvd", "kev", "osv", "github_advisory"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", re.DOTALL)
KV_RE = re.compile(r"^([A-Za-z_]\w*):\s*(.*)$")
FM_KEYS = ("title", "source", "url", "publish_time", "summary_zh")  # 防止正文以 --- 开头被误判
IMG_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
REF_RE = re.compile(r"^-\s*Ref:")

CHUNK_TARGET = 700
CHUNK_OVERLAP = 100


def parse_frontmatter(text: str) -> tuple[dict, str | None]:
    """返回 (meta, body)。无 frontmatter 时 meta={} 且 body=None（由调用方回退）。"""
    if not text.startswith("---"):
        return {}, None
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}, None
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        kv = KV_RE.match(line.strip())
        if kv:
            meta[kv.group(1)] = kv.group(2).strip().strip('"').strip("'")
    if not any(k in meta for k in FM_KEYS):
        return {}, None                  # 不含已知键：是正文不是 frontmatter
    return meta, m.group(2)


def clean_body(body: str) -> str:
    # 残缺的 markdown 链接/图片语法可能一轮清洗后留下新可匹配碎片，迭代到不动点
    for _ in range(3):
        cleaned = _clean_once(body)
        if cleaned == body:
            return cleaned
        body = cleaned
    return body


def _clean_once(body: str) -> str:
    body = IMG_RE.sub(" ", body)          # 图片链接整段去掉
    body = LINK_RE.sub(r"\1", body)       # 普通链接只留锚文本
    lines: list[str] = []
    seen_ref: set[str] = set()
    for line in body.splitlines():
        if REF_RE.match(line.strip()):
            if line in seen_ref:
                continue                  # CVE 的 Ref 行全库去重
            seen_ref.add(line)
        lines.append(line.rstrip())
    body = "\n".join(lines)
    body = re.sub(r"\n{3,}", "\n\n", body)
    return body.strip()


def chunk_text(text: str, target: int = CHUNK_TARGET, overlap: int = CHUNK_OVERLAP) -> list[str]:
    paragraphs = [p.strip() for p in text.split("\n") if p.strip()]
    units: list[str] = []
    for p in paragraphs:
        while len(p) > target * 1.5:
            cut = p.rfind("。", 0, target)
            cut = cut + 1 if cut > target // 2 else target
            units.append(p[:cut])
            p = p[max(cut - overlap, 0):]
        if p:
            units.append(p)

    chunks: list[str] = []
    buf = ""
    for u in units:
        if buf and len(buf) + len(u) + 1 > target:
            chunks.append(buf)
            buf = buf[-overlap:] + "\n" + u if overlap else u
        else:
            buf = f"{buf}\n{u}" if buf else u
    if buf:
        chunks.append(buf)
    return chunks


def load_vuln_meta() -> dict[str, dict]:
    if not INDEX_DB.exists():
        print("[warn] index.sqlite 不存在，CVE 不拼接富化字段")
        return {}
    try:
        con = sqlite3.connect(f"file:{INDEX_DB.as_posix()}?mode=ro", uri=True)
        rows = con.execute(
            "SELECT cve_id, ai_related, summary_zh, affected_component FROM vuln_meta"
        ).fetchall()
        con.close()
        return {r[0]: {"ai_related": r[1], "summary_zh": r[2] or "", "component": r[3] or ""}
                for r in rows}
    except sqlite3.Error as e:
        print(f"[warn] index.sqlite 读取失败（忽略）: {e}")
        return {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只统计不写任何文件")
    args = ap.parse_args()

    t0 = time.time()
    # 旧 sidecar（幂等回退用，flat 记录去掉 file 字段即元数据）
    old_meta: dict[str, dict] = {}
    if META_JSONL.exists():
        with META_JSONL.open(encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                old_meta[rec["file"]] = {k: v for k, v in rec.items() if k != "file"}
        print(f"[init] 读到旧元数据 {len(old_meta)} 条（幂等回退）")

    vuln_meta = load_vuln_meta()
    files = sorted(p for p in EXPORT_DIR.rglob("*.md") if p.is_file())
    print(f"[init] 待处理 {len(files)} 个文件")

    meta_out = None if args.dry_run else META_JSONL.open("w", encoding="utf-8")
    chunk_out = None if args.dry_run else CHUNKS_JSONL.open("w", encoding="utf-8")
    stat: Counter = Counter()
    chunk_len_all: list[int] = []
    changed = 0

    for n, path in enumerate(files, 1):
        rel = path.relative_to(EXPORT_DIR).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        meta, body = parse_frontmatter(text)
        if body is None:                      # 已清洗过的文件：从 sidecar 回读元数据
            meta = old_meta.get(rel, {})
            body = text
        title = meta.get("title") or path.stem
        source = meta.get("source") or path.parent.name
        url = meta.get("url", "")
        publish_time = meta.get("publish_time", "")
        domain = "cve" if source in CVE_SOURCES else "article"

        cleaned = clean_body(body)
        if cleaned != body:
            changed += 1
            if not args.dry_run:
                path.write_text(cleaned, encoding="utf-8", newline="\n")
        body = cleaned

        if meta_out:
            meta_out.write(json.dumps({
                "file": rel, "domain": domain, "source": source, "url": url,
                "title": title, "publish_time": publish_time,
                **({"summary_zh": meta["summary_zh"]} if meta.get("summary_zh") else {}),
            }, ensure_ascii=False) + "\n")

        cve_ids = sorted(set(CVE_RE.findall(f"{title}\n{body}")))[:10]
        if domain == "cve":
            vm = vuln_meta.get(cve_ids[0], {}) if cve_ids else {}
            parts = [title]
            if vm.get("summary_zh"):
                parts.append("中文摘要: " + vm["summary_zh"])
            parts.append(body)
            if vm.get("component"):
                parts.append(f"组件: {vm['component']}")
            assembled = "\n".join(parts)
            if len(assembled) > 2000:        # 超长公告（osv/gh_advisory 全文）也切块
                pieces = chunk_text(assembled)
                texts = [f"{title} ({i+1}/{len(pieces)})\n{c}"
                         for i, c in enumerate(pieces)]
            else:
                texts = [assembled]
        else:
            anchor = f"{title} | {source} | {publish_time[:10]}\n"
            texts = [anchor + c for c in chunk_text(body)]

        vm_meta = vuln_meta.get(cve_ids[0]) if cve_ids else None
        n_chunks = len(texts)
        for i, chunk in enumerate(texts):
            rec = {
                "id": hashlib.sha1(f"{rel}#{i}".encode()).hexdigest(),
                "file": rel, "domain": domain, "source": source, "url": url,
                "title": title[:300], "publish_time": publish_time,
                "chunk_index": i, "n_chunks": n_chunks,
                "cve_ids": ",".join(cve_ids),
                "ai_related": int(bool(vm_meta and vm_meta.get("ai_related"))),
                "text": chunk,
            }
            if chunk_out:
                chunk_out.write(json.dumps(rec, ensure_ascii=False) + "\n")

        stat[f"{domain}/{source}"] += 1
        chunk_len_all.extend(len(t) for t in texts)
        if n % 4000 == 0:
            print(f"[run] {n}/{len(files)} 已清洗 {changed} | 已出块 "
                  f"{len(chunk_len_all)} | {time.time()-t0:.0f}s", flush=True)

    if meta_out:
        meta_out.close()
    if chunk_out:
        chunk_out.close()

    lens = chunk_len_all
    print(f"\n[done] 文件 {len(files)} | 原地清洗 {changed} | 出块 {len(lens)} | "
          f"耗时 {(time.time()-t0)/60:.1f}min")
    print(f"块长: min {min(lens)} / avg {sum(lens)//len(lens)} / max {max(lens)} / "
          f"超2000字 {sum(1 for l in lens if l > 2000)}")
    print(f"块数 top10:")
    for k, v in stat.most_common(10):
        print(f"  {k}: {v} 文件")
    if not args.dry_run:
        print(f"产物: {META_JSONL.name}({META_JSONL.stat().st_size//1024}KB), "
              f"{CHUNKS_JSONL.name}({CHUNKS_JSONL.stat().st_size//2**20}MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

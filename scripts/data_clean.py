#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
data_clean.py —— 存量数据清洗（T1，一次性迁移，幂等可重跑）

对已有的脏数据做七件事（新数据已由爬虫写入端质量门保证，不会再产生这些）：
  1. type 回填：640 条空 type 按 url/source 推断回填
  2. 未来日期修正：先知 UTC+8 归一；其余未来日期 clamp 到今天
  3. 污染清洗：content_md 里 HTML 实体还原 + 残留标签剥离（审计 0.6%）
  4. 长度门回溯：文章类 1~300 字的完整短文标 low_content（不入索引）
  5. ai_signal 分级回填：CPE 组件名精确命中=strong，其余 AI 命中=weak（待 LLM 复核）
  6. 拦截页回滚：滑块/验证码页混充正文的清空正文标 detail_failed（FreeBuf 事故存量）
  7. url_norm 规范化去重：同一篇文章不同跟踪参数保长弃短合并为一条

用法：uv run python scripts/data_clean.py [--out-dir ./data] [--dry-run]
"""

import argparse
import html as html_mod
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent))
from xianzhi_crawler import infer_record_type, norm_url

TAG_RE = re.compile(r"<[^>]+>\s*")
WS_RE = re.compile(r"[ \t]{2,}")
POLLUTE = re.compile(r"<div|&nbsp;|javascript:|function\(|\ufffd")


def clean_md(md: str) -> str:
    return WS_RE.sub(" ", TAG_RE.sub(" ", html_mod.unescape(md))).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="./data")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    db = sqlite3.connect(Path(args.out_dir) / "index.sqlite")
    today = datetime.now().strftime("%Y-%m-%d %H:%M")
    changes = {"type": 0, "future_date": 0, "pollution": 0, "low_content": 0, "ai_signal": 0,
               "intercept": 0, "url_dup": 0}

    # 1. type 回填
    rows = db.execute("SELECT url, source FROM records WHERE type IS NULL OR type=''").fetchall()
    for url, source in rows:
        t = infer_record_type(url, source)
        if t:
            db.execute("UPDATE records SET type=? WHERE url=?", (t, url))
            changes["type"] += 1

    # 2. 未来日期修正：先知是 UTC（+8h 归一），其余 clamp
    rows = db.execute("SELECT url, publish_time FROM records WHERE publish_time > ?", (today,)).fetchall()
    for url, pt in rows:
        try:
            new_pt = pt
            if "xz.aliyun.com" in url:
                new_pt = (datetime.strptime(pt[:16], "%Y-%m-%d %H:%M") + timedelta(hours=8)) \
                    .strftime("%Y-%m-%d %H:%M")
            if new_pt > today:   # 仍超前的 clamp 到今天
                new_pt = today
            db.execute("UPDATE records SET publish_time=? WHERE url=?", (new_pt, url))
            changes["future_date"] += 1
        except ValueError:
            pass

    # 3. 污染清洗（幂等：POLLUTE 会命中 javascript:/function( 等正文固有词，clean_md 清不掉；
    #    只有内容真的变了才写库，避免每次运行重复计数——2026-10-03 修复）
    rows = db.execute("SELECT url, content_md FROM records WHERE length(content_md)>200").fetchall()
    for url, md in rows:
        if POLLUTE.search(md):
            cleaned = clean_md(md)
            if cleaned != md:
                db.execute("UPDATE records SET content_md=? WHERE url=?", (cleaned, url))
                changes["pollution"] += 1

    # 4. 长度门回溯：文章类完整短文（有正文但 <300 字）标 low_content
    changes["low_content"] = db.execute("""UPDATE records SET status='low_content'
        WHERE status='enriched' AND (type IN ('article','rss_article'))
        AND length(content_md) BETWEEN 1 AND 299""").rowcount

    # 5. ai_signal 回填：CNNVD 来源的 AI 判定视为强信号；已有 matched 里含 CPE 类组件名的判强
    db.execute("""CREATE TABLE IF NOT EXISTS vuln_meta(
        cve_id TEXT PRIMARY KEY, cvss REAL, severity TEXT, kev INTEGER, epss TEXT,
        cpes TEXT, ai_related INTEGER, matched TEXT, ai_signal TEXT DEFAULT '', updated_at TEXT)""")
    cols = {r[1] for r in db.execute("PRAGMA table_info(vuln_meta)").fetchall()}
    if "ai_signal" not in cols:
        db.execute("ALTER TABLE vuln_meta ADD COLUMN ai_signal TEXT DEFAULT ''")
    changes["ai_signal"] = db.execute("""UPDATE vuln_meta SET ai_signal='strong'
        WHERE ai_related=1 AND (matched LIKE '%CNNVD-AIVD%' OR cpes LIKE '%a:langchain%'
        OR cpes LIKE '%a:mlflow%' OR cpes LIKE '%a:vllm%' OR cpes LIKE '%a:ollama%')""").rowcount
    db.execute("UPDATE vuln_meta SET ai_signal='weak' WHERE ai_related=1 AND (ai_signal IS NULL OR ai_signal='')")

    # 6. 拦截页污染回滚（2026-10-02 复查发现 338 条 FreeBuf 滑块页残留，写入端质量门前移后复发已堵住）：
    #    清空正文标 detail_failed，冷却后 deep_fill --retry-failed 可重抓
    changes["intercept"] = db.execute("""UPDATE records SET content_md='', status='detail_failed'
        WHERE length(content_md)>0 AND (
            content_md LIKE '%请按住滑块%' OR content_md LIKE '%拖动到最右边%'
            OR content_md LIKE '%访问过于频繁%' OR content_md LIKE '%环境异常%'
            OR content_md LIKE '%完成验证后%' OR content_md LIKE '%拖动滑块完成验证%'
            OR content_md LIKE '%CF_APP_WAF%'
            OR lower(substr(content_md,1,800)) LIKE '%captcha%')""").rowcount

    # 7. url_norm 规范化去重（补原设计 §1.5 的缺口）：同一篇文章带不同跟踪参数只留一条，
    #    保长弃短（保留正文最长的行）；url_norm 空值由 Store 首次打开库时自动回填
    cols = {r[1] for r in db.execute("PRAGMA table_info(records)").fetchall()}
    if "url_norm" not in cols:
        db.execute("ALTER TABLE records ADD COLUMN url_norm TEXT DEFAULT ''")
    rows = db.execute("SELECT url FROM records WHERE url_norm=''").fetchall()
    if rows:
        db.executemany("UPDATE records SET url_norm=? WHERE url=?",
                       [(norm_url(u), u) for (u,) in rows])
    removed = 0
    for (un,) in db.execute("""SELECT url_norm FROM records WHERE url_norm!=''
            GROUP BY url_norm HAVING count(*)>1""").fetchall():
        dup = db.execute("""SELECT url FROM records WHERE url_norm=?
            ORDER BY length(content_md) DESC, crawl_time DESC""", (un,)).fetchall()
        for (u,) in dup[1:]:
            db.execute("DELETE FROM records WHERE url=?", (u,))
            removed += 1
    changes["url_dup"] = removed

    if args.dry_run:
        db.rollback()
        print("[dry-run] 将执行的变更：", changes)
    else:
        db.commit()
        print("清洗完成：", changes)
    # 质量面板
    print("\n== 质量面板 ==")
    print("type 分布:", db.execute("SELECT type, count(*) FROM records GROUP BY type ORDER BY 2 DESC").fetchall())
    print("status 分布:", db.execute("SELECT status, count(*) FROM records GROUP BY status").fetchall())
    print("type 空值:", db.execute("SELECT count(*) FROM records WHERE type IS NULL OR type=''").fetchone()[0])
    print("未来日期:", db.execute("SELECT count(*) FROM records WHERE publish_time > ?", (today,)).fetchone()[0])
    print("ai_signal 分布:", db.execute("SELECT ai_signal, count(*) FROM vuln_meta GROUP BY ai_signal").fetchall())


if __name__ == "__main__":
    main()

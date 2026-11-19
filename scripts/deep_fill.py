#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
正文补全器（deep_fill）—— 补齐两级采集架构的最后一环

背景：rss_collector.py 是浅抓（只有标题+链接+摘要），答不了内容级问题。
本脚本对没有正文的 rss_article/article 记录抓原文页，用 trafilatura 通用
正文抽取（不需要每站写选择器），失败再上 Playwright 无头浏览器兜底。
全量很小（关键词粗筛后每月百余条），成本可忽略。

用法：
    uv run python scripts/deep_fill.py                 # 补全所有空正文文章
    uv run python scripts/deep_fill.py --limit 5       # 试跑5条
    uv run python scripts/deep_fill.py --retry-failed  # 连 detail_failed 的一起重试
产出：records.content_md 更新（DB 是当前权威状态，JSONL 是入库流水），
原始 HTML 存 data/raw/articles/。
"""

import argparse
import hashlib
import html as html_mod
import re
import time
from pathlib import Path

import requests
import trafilatura

from xianzhi_crawler import Store, UA, now_iso, playwright_fetch, is_intercept

TAG_RE = re.compile(r"<[^>]+>\s*")
WS_RE = re.compile(r"[ \t]{2,}")
# robots.txt Crawl-Delay 合规：按 host 覆盖默认间隔（2026-09-27 审计发现 Krebs 要求 35s）
HOST_DELAYS = {"krebsonsecurity.com": 35.0}


def sleep_for(url: str, base: float):
    """按目标站 robots 的 Crawl-Delay 取间隔（未声明的用基础间隔）。"""
    from urllib.parse import urlparse
    host = urlparse(url).netloc.replace("www.", "")
    time.sleep(max(base, HOST_DELAYS.get(host, 0)))
# 拦截页特征与 is_intercept 已上移至 xianzhi_crawler（写入端 Store.upsert 统一把关），此处 import 复用


def clean_md(md: str) -> str:
    """写入端质量门②：HTML 实体还原 + 残留标签剥离。"""
    if not md:
        return md
    md = html_mod.unescape(md)
    md = TAG_RE.sub(" ", md)
    return WS_RE.sub(" ", md).strip()


def extract_md(html: str) -> str:
    """trafilatura 抽正文并转 markdown；识别失败返回空串。"""
    try:
        return trafilatura.extract(html, output_format="markdown",
                                   include_comments=False, favor_recall=True) or ""
    except Exception:
        return ""


def fill_one(sess: requests.Session, url: str, store: Store) -> str:
    aid = hashlib.sha1(url.encode()).hexdigest()[:16]
    html = ""
    try:
        r = sess.get(url, headers={"User-Agent": UA}, timeout=20)
        html = r.text if r.status_code == 200 else ""
    except requests.RequestException as e:
        print(f"  [warn] {type(e).__name__}: {url[:60]}")
    md = extract_md(html) if html else ""
    # 拦截页（滑块/环境异常）即使字数够也是假的 → 无头浏览器兜底重抓
    if len(md) < 200 or is_intercept(md):
        html2 = playwright_fetch(url)
        if html2:
            md2 = extract_md(html2) or ""
            if not is_intercept(md2):
                md = md2
            html = html or html2
    if is_intercept(md):   # 兜底后仍是拦截页 → 交回上层判失败
        return ""
    if html:
        raw_articles = store.raw_detail.parent.parent / "articles"   # raw/articles（与来源无关）
        raw_articles.mkdir(parents=True, exist_ok=True)
        (raw_articles / f"{aid}.html").write_text(html, encoding="utf-8")
    return md


def main():
    ap = argparse.ArgumentParser(description="正文补全器")
    ap.add_argument("--limit", type=int, default=0, help="只补 N 条（试跑用）")
    ap.add_argument("--retry-failed", action="store_true", help="连 detail_failed 的一起重试")
    ap.add_argument("--sleep", type=float, default=1.5, help="间隔秒数")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    store = Store(Path(args.out_dir))
    cond = "(content_md IS NULL OR content_md='')"
    if not args.retry_failed:
        cond += " AND status != 'detail_failed'"
    # 合规门：no_body（平台放弃/付费）与付费标记的记录永不抓取正文
    cond += " AND status != 'no_body' AND tags NOT LIKE '%付费%'"
    # 补天详情需要登录态（由 butian_crawler --with-cookie 专门处理），通用补全跳过
    cond += " AND source != 'butian'"
    rows = store.db.execute(
        f"SELECT url, title FROM records WHERE {cond} "
        f"AND (type IN ('article','rss_article') OR type IS NULL OR type='')").fetchall()
    if args.limit:
        rows = rows[:args.limit]
    print(f"待补正文 {len(rows)} 条")

    sess = requests.Session()
    ok = fail = 0
    for i, (url, title) in enumerate(rows, 1):
        print(f"[{i}/{len(rows)}] {title[:40]}")
        if "mp.weixin.qq.com" in url:
            # 微信正文：验证码级风控（真实 Chrome 实测也拦），平台性放弃——标记 no_body 不再重试
            store.db.execute("UPDATE records SET status='no_body', crawl_time=? WHERE url=?",
                             (now_iso(), url))
            store.db.commit()
            fail += 1
            continue
        md = clean_md(fill_one(sess, url, store))
        # 质量门③a：反爬拦截页（滑块/环境异常）→ 判失败走 Playwright 兜底重试
        if is_intercept(md):
            md = ""
        # 写入端质量门③：长度门——>=300 字才 enriched；1~300 字完整短文标 low_content 不入索引；
        # 空为 detail_failed 可重试
        if len(md) >= 300:
            status = "enriched"
            ok += 1
        elif len(md) > 0:
            status = "low_content"
            fail += 1
        else:
            status = "detail_failed"
            fail += 1
        store.db.execute("UPDATE records SET content_md=?, status=?, crawl_time=? WHERE url=?",
                         (md, status, now_iso(), url))
        store.db.commit()
        sleep_for(url, args.sleep)
    print(f"完成：成功 {ok}，失败 {fail}（失败的可再跑本脚本或人工检查 raw/articles/）")


if __name__ == "__main__":
    main()

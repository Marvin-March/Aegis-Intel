#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全内参（secrss.com）AI 安全文章爬虫 —— L1 专项源（全站即 AI 安全聚合）

原理：
1. 列表服务端渲染：GET /articles?tag=人工智能&page=N，绝对链接
   https://www.secrss.com/articles/{id}，无需隐藏接口；
2. 详情页服务端渲染（article-body），trafilatura 直接抽 markdown；
3. 统一记录格式入 Store（source=secrss，type=article），url 判重增量；
4. 礼貌间隔 1.2s，原始 HTML 归档 raw/secrss/。

用法：
    uv run python scripts/secrss_crawler.py                    # 列表回填 50 页 + 正文
    uv run python scripts/secrss_crawler.py --pages 1 --detail-limit 3   # 试跑
    uv run python scripts/secrss_crawler.py --no-tag           # 全站（不限 AI 标签）
"""

import argparse
import hashlib
import re
import time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

from xianzhi_crawler import Store, UA, now_iso
from deep_fill import clean_md

BASE = "https://www.secrss.com"
LIST_URL = f"{BASE}/articles"


def list_urls(html: str) -> list:
    """从列表页提取文章绝对链接（去重保序）。"""
    seen, out = set(), []
    for m in re.finditer(r'href="(https?://www\.secrss\.com/articles/(\d+))"', html):
        url, aid = m.group(1), m.group(2)
        if url not in seen:
            seen.add(url)
            out.append((url, aid))
    return out


def id_scan(sess: requests.Session, start: int, stop: int, store: Store, out_dir: Path,
            sleep: float, min_len: int = 200) -> dict:
    """
    【已弃用——勿用】ID 递减扫描：实测 82% 探测为 404 无效请求（146/178），属于
    大量无效爆破，不符合礼貌原则。历史数据通过每日增量自然积累即可。
    保留代码仅作记录，CLI 入口已移除。
    """
    """
    ID 递减扫描（历史回填）：站点不支持 URL 分页，但文章 ID 近似单调。
    安全内参文章 ID 稀疏（93000 可 404 而 92919 存在），按 1.2s 礼貌逐个探测。
    扫描记录落盘（scanned_ids.txt），重跑不重复探测。
    """
    import trafilatura
    done_file = Path(out_dir) / "raw" / "secrss" / "scanned_ids.txt"
    done_file.parent.mkdir(parents=True, exist_ok=True)
    done = set(done_file.read_text().split()) if done_file.exists() else set()
    ok = dup = miss = 0
    for aid in range(start, stop - 1, -1):
        key = str(aid)
        if key in done:
            continue
        url = f"{BASE}/articles/{aid}"
        if store.seen(url):
            done.add(key)
            dup += 1
        else:
            try:
                r = sess.get(url, timeout=20)
            except requests.RequestException:
                continue                      # 网络错误不记 done，下轮重试
            if r.status_code != 200:
                done.add(key)
                miss += 1
            else:
                html = r.text
                (done_file.parent / f"{aid}.html").write_text(html, encoding="utf-8")
                md = ""
                try:
                    import trafilatura as tf
                    md = clean_md(tf.extract(html, output_format="markdown",
                                             include_comments=False) or "")
                except Exception:
                    pass
                title_m = re.search(r"<title>(.*?)\s*-\s*安全内参", html, re.I)
                date_m = re.search(r"20\d{2}-\d{2}-\d{2}", html)
                if len(md) >= min_len:
                    rec = {
                        "id": f"secrss-{aid}",
                        "source": "secrss",
                        "type": "article",
                        "url": url,
                        "title": title_m.group(1).strip() if title_m else f"secrss-{aid}",
                        "summary": md[:300],
                        "publish_time": (date_m.group(0) if date_m else ""),
                        "tags": ["secrss", "AI", "人工智能"],
                        "crawl_time": now_iso(),
                        "content_md": md,
                    }
                    store.upsert(rec, "enriched" if len(md) >= 300 else "low_content")
                    ok += 1
                else:
                    miss += 1                 # 200 但非文章页（聚合页/空壳）
                done.add(key)
            time.sleep(sleep)
        if aid % 100 == 0:
            done_file.write_text("\n".join(sorted(done, key=int)), encoding="utf-8")
            print(f"  扫描进度 id={aid}（新增 {ok}，已见 {dup}，无效 {miss}）")
    done_file.write_text("\n".join(sorted(done, key=int)), encoding="utf-8")
    return {"ok": ok, "dup": dup, "miss": miss}


def crawl_list(sess: requests.Session, pages: int, use_tag: bool, store: Store, sleep: float) -> list:
    """翻页抓列表，返回新文章 (url, aid) 列表（老文章跳过）。"""
    tag = "%E4%BA%BA%E5%B7%A5%E6%99%BA%E8%83%BD" if use_tag else ""
    new_items, seen_this_run = [], set()
    for page in range(1, pages + 1):
        q = f"?tag={tag}&page={page}" if use_tag else f"?page={page}"
        try:
            r = sess.get(f"{LIST_URL}{q}", timeout=20)
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"  [warn] 列表第{page}页 {type(e).__name__}")
            break
        items = list_urls(r.text)
        fresh = [(u, a) for u, a in items if u not in seen_this_run and not store.seen(u)]
        print(f"  列表第{page}页: {len(items)} 条, 新 {len(fresh)} 条")
        if not items:
            break
        if not fresh and page > 1:      # 整页都是老的 → 增量到底了
            break
        new_items.extend(fresh)
        seen_this_run.update(u for u, _ in items)
        time.sleep(sleep)
    return new_items


def fetch_detail(sess: requests.Session, url: str, store: Store) -> str:
    try:
        r = sess.get(url, timeout=20)
        if r.status_code != 200:
            return ""
        html = r.text
        aid = url.rstrip("/").split("/")[-1]
        raw_dir = Path(store.raw_detail).parent / "secrss"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / f"{aid}.html").write_text(html, encoding="utf-8")
        import trafilatura
        md = trafilatura.extract(html, output_format="markdown", include_comments=False) or ""
        return clean_md(md)
    except requests.RequestException as e:
        print(f"  [warn] 详情 {type(e).__name__}: {url[:60]}")
        return ""


def main():
    ap = argparse.ArgumentParser(description="安全内参 AI 安全文章爬虫")
    ap.add_argument("--pages", type=int, default=50, help="列表页数（每页约 40 条）")
    ap.add_argument("--detail-limit", type=int, default=0, help="最多抓几篇正文（0=不限）")
    ap.add_argument("--no-tag", action="store_true", help="不限 AI 标签，抓全站")
    ap.add_argument("--no-detail", action="store_true", help="只抓列表元数据")
    ap.add_argument("--sleep", type=float, default=1.2)
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    store = Store(Path(args.out_dir))
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    items = crawl_list(sess, args.pages, not args.no_tag, store, args.sleep)
    print(f"列表新增 {len(items)} 条")

    n = 0
    for url, aid in items:
        rec = {
            "id": f"secrss-{aid}",
            "source": "secrss",
            "type": "article",
            "url": url,
            "title": "",               # 详情阶段回填
            "summary": "",
            "publish_time": "",
            "tags": ["secrss", "AI", "人工智能"],
            "crawl_time": now_iso(),
            "content_md": "",
        }
        if not store.seen(url):
            store.upsert(rec, "listed")
            n += 1
    print(f"入库 {n} 条")

    if args.no_detail:
        return
    rows = store.db.execute("""SELECT url FROM records WHERE source='secrss'
        AND (content_md IS NULL OR content_md='') AND status NOT IN ('detail_failed')""").fetchall()
    if args.detail_limit:
        rows = rows[:args.detail_limit]
    print(f"待抓正文 {len(rows)} 篇")
    ok = fail = 0
    for i, (url,) in enumerate(rows, 1):
        md = fetch_detail(sess, url, store)
        aid = url.rstrip("/").split("/")[-1]
        title = ""
        status = "enriched" if len(md) >= 300 else ("low_content" if md else "detail_failed")
        if md:
            # 从详情页 <title> 取标题（格式：xxx - 安全内参 | …）
            m = re.search(r"<title>([^<]+?)\s*-\s*安全内参", open(
                Path(store.raw_detail).parent / "secrss" / f"{aid}.html",
                encoding="utf-8").read(), re.I) if (Path(store.raw_detail).parent / "secrss" / f"{aid}.html").exists() else None
            title = m.group(1).strip() if m else ""
            ok += 1
        else:
            fail += 1
        store.db.execute("""UPDATE records SET content_md=?, status=?, title=CASE WHEN ?!='' THEN ? ELSE title END,
            crawl_time=? WHERE url=?""", (md, status, title, title, now_iso(), url))
        store.db.commit()
        time.sleep(args.sleep)
    print(f"完成：成功 {ok}，失败 {fail}")


if __name__ == "__main__":
    main()

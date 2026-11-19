#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
补天攻防社区 AI 专栏爬虫（forum.butian.net/AISecurity）—— L1 专项源（厂商生态）

结构（2026-09-26 侦察）：
- 列表：/AISecurity?page=N 服务端渲染，每页 20 篇，含标题/摘要/作者/时间，无需登录
- 详情：/ai_security/{id} 未登录=正文模糊+登录浮层（站点访问控制，不绕过）
  → 带 BUTIAN_COOKIE（.env，免费注册账号的登录 cookie）即可正常阅读抓取

模式：
  默认            列表元数据回填（无需登录，约 18 页）
  --with-cookie   详情正文抓取（读 .env 的 BUTIAN_COOKIE，需账号）

用法：
    uv run python scripts/butian_crawler.py                     # 元数据回填
    uv run python scripts/butian_crawler.py --pages 25
    uv run python scripts/butian_crawler.py --with-cookie       # 登录态补正文
"""

import argparse
import hashlib
import json
import re
import time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

from xianzhi_crawler import Store, UA, now_iso

BASE = "https://forum.butian.net"
LIST_URL = f"{BASE}/AISecurity"


def parse_list(html: str) -> list:
    """从列表页提取 (文章URL, 标题, 摘要, 作者, 时间)。"""
    soup = BeautifulSoup(html, "html.parser")
    out, seen = [], set()
    for a in soup.select('a[href*="/ai_security/"]'):
        href = a.get("href", "")
        m = re.search(r"/ai_security/(\d+)", href)
        if not m:
            continue
        url = f"{BASE}/ai_security/{m.group(1)}"
        if url in seen:
            continue
        seen.add(url)
        # 从条目容器提取标题/摘要/作者/时间
        container = a.find_parent(["div", "li", "article"]) or a
        text = container.get_text("\n", strip=True).split("\n")
        title = a.get_text(strip=True)
        author, ptime = "", ""
        for line in text:
            if " 发布于 " in line:
                ptime = line.split(" 发布于 ")[-1].strip()[:16]
                break
        author_el = container.select_one("a[href*='/people/']")
        if author_el:
            author = author_el.get_text(strip=True)
        out.append({"url": url, "aid": m.group(1), "title": title,
                    "summary": "", "author": author, "publish_time": ptime})
    return out


def parse_summary(container_text: str) -> str:
    m = re.search(r"摘要：(.+?)(?:阅读|发布|\Z)", container_text, re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:500] if m else ""


def fetch_detail(sess: requests.Session, url: str, cookie: str, store: Store, aid: str) -> tuple:
    headers = {"User-Agent": UA, "Referer": BASE}
    if cookie:
        sess.headers["Cookie"] = cookie
    try:
        r = sess.get(url, timeout=20)
        html = r.text if r.status_code == 200 else ""
    except requests.RequestException:
        return "", ""
    if not html:
        return "", ""
    raw_dir = Path(store.raw_detail).parent / "butian"
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / f"{aid}.html").write_text(html, encoding="utf-8")
    soup = BeautifulSoup(html, "html.parser")
    # 补天正文容器（实测）：div.widget-article 含完整文章（标题+标签+摘要+正文+代码）
    body = soup.select_one(".widget-article") or soup.select_one(".article-body") or soup
    text = body.get_text("\n", strip=True)
    title_m = re.search(r"<title>([^<]+)", html)
    title = title_m.group(1).split("_")[0].split("-")[0].strip() if title_m else ""
    import trafilatura
    md = trafilatura.extract(html, output_format="markdown", include_comments=False,
                             favor_recall=True) or ""
    # trafilatura 抽不全时（实测它抓到导航而非正文），用 BeautifulSoup 直接取 widget-article
    if len(md) < 500 or "Toggle navigation" in md:
        md = text  # 降级为纯文本（去掉 HTML 标签但保留完整内容）
    return md, title


def main():
    ap = argparse.ArgumentParser(description="补天攻防社区 AI 专栏爬虫")
    ap.add_argument("--pages", type=int, default=25, help="列表页数（每页 20 条）")
    ap.add_argument("--with-cookie", action="store_true",
                    help="读 .env 的 BUTIAN_COOKIE 抓正文（需免费注册账号）")
    ap.add_argument("--sleep", type=float, default=1.5)
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    cookie = ""
    if args.with_cookie:
        env = Path(".env")
        if env.exists():
            m = re.search(r"BUTIAN_COOKIE=([^\n]+)", env.read_text(encoding="utf-8"))
            cookie = m.group(1).strip() if m else ""
        if not cookie:
            print("[warn] --with-cookie 但 .env 无 BUTIAN_COOKIE，退化为元数据模式")

    store = Store(Path(args.out_dir))
    sess = requests.Session()
    sess.headers.update({"User-Agent": UA})

    # 阶段一：列表元数据回填
    n_new, pages_done = 0, 0
    for page in range(1, args.pages + 1):
        q = f"?page={page}" if page > 1 else ""
        try:
            r = sess.get(f"{LIST_URL}{q}", timeout=20)
        except requests.RequestException as e:
            print(f"  [warn] 列表第{page}页 {type(e).__name__}")
            break
        items = parse_list(r.text)
        if not items:
            break
        fresh = 0
        for it in items:
            if store.seen(it["url"]):
                continue
            rec = {
                "id": f"butian-{it['aid']}",
                "source": "butian",
                "type": "article",
                "url": it["url"],
                "title": it["title"],
                "summary": it["summary"],
                "publish_time": it["publish_time"],
                "tags": ["butian", "AI安全技术", "AI"]
                        + ([f"作者:{it['author']}"] if it["author"] else []),
                "crawl_time": now_iso(),
                "content_md": "",
            }
            store.upsert(rec, "listed")
            fresh += 1
        pages_done += 1
        n_new += fresh
        print(f"  列表第{page}页: {len(items)} 条, 新 {fresh} 条")
        if fresh == 0 and page > 1:
            print("  整页已存在，增量到底")
            break
        time.sleep(args.sleep)
    print(f"[butian] 列表完成：{pages_done} 页，新增 {n_new} 条")

    # 阶段二：正文（登录态）
    if not (args.with_cookie and cookie):
        print("正文抓取需要登录态：注册补天账号后把 cookie 存入 .env（BUTIAN_COOKIE=…），"
              "再跑 --with-cookie。未登录详情页为模糊墙（站点访问控制，不绕过）。")
        return
    rows = store.db.execute("""SELECT url FROM records WHERE source='butian'
        AND (content_md IS NULL OR content_md='') AND status NOT IN ('no_body','detail_failed')""").fetchall()
    print(f"待抓正文 {len(rows)} 篇（登录态）")
    sess.headers["Cookie"] = cookie
    ok = fail = 0
    from bs4 import BeautifulSoup as BS
    for i, (url,) in enumerate(rows, 1):
        try:
            r = sess.get(url, headers={"User-Agent": UA, "Referer": BASE}, timeout=20)
            html = r.text if r.status_code == 200 else ""
        except requests.RequestException:
            html = ""
        md = ""
        if html:
            soup = BS(html, "html.parser")
            body = soup.select_one(".widget-article")   # 补天正文容器（实测 cookie 登录后完整可读）
            if body:
                md = body.get_text("\n", strip=True)
        status = "enriched" if len(md) >= 300 else "detail_failed"
        ok, fail = (ok + 1, fail) if status == "enriched" else (ok, fail + 1)
        store.db.execute("""UPDATE records SET content_md=?, status=?, crawl_time=? WHERE url=?""",
                         (md, status, now_iso(), url))
        store.db.commit()
        print(f"  [{i}/{len(rows)}] {'✅' if md else '❌'} {len(md)}字 | {(md or '')[:40]}")
        time.sleep(args.sleep)
    print(f"完成：成功 {ok}，失败 {fail}")


if __name__ == "__main__":
    main()

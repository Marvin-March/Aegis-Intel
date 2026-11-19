#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
先知社区（xz.aliyun.com）文章爬虫 —— 列表接口 + 详情兜底版

原理（为什么这么写）：
1. 列表不走网页，走隐藏 AJAX 接口（F12 -> Network -> XHR 找到的）：
   GET https://xz.aliyun.com/news?isAjax=true&type=category&category={cid}&cate_id=0&page={n}
   必须带头 X-Requested-With: XMLHttpRequest，否则返回整页 HTML 而不是 JSON。
   不带 type/category 参数 = 全站所有分类。
   JSON 里 data 字段是本页文章列表的 HTML 片段，pagination 字段含最大页码。
2. 详情页有阿里云 WAF 的 JS 挑战（响应里出现 renderData/acw_sc 标记），
   requests 拿到的是挑战页不是正文 —— 检测到就自动切 Playwright 无头浏览器兜底。
3. 所有产出转统一记录格式（见 架构设计-怎么搭.md 第二节），source+url 判重，SQLite 建索引。
4. 限速：默认列表间隔 2s、详情间隔 1.5s；重试 2 次指数退避。单条失败跳过不毁整批。
5. 注意：列表接口返回的 publish_time 是 UTC（比网页显示早 8 小时），入库后统一转北京时间。

依赖（写进 pyproject.toml，用 uv）：
    uv add requests beautifulsoup4 markdownify
    uv add playwright && playwright install chromium   # 可选：仅详情页 WAF 兜底需要

用法：
    python xianzhi_crawler.py                        # 默认：AI专栏(28) 列表+详情，增量
    python xianzhi_crawler.py --list-only            # 只要编号和元数据（快，1分钟出全量清单）
    python xianzhi_crawler.py --all                  # 全站全部分类
    python xianzhi_crawler.py --category 2           # 指定分类：2=漏洞分析 14=WEB安全 15=移动安全 28=AI专栏
    python xianzhi_crawler.py --max-pages 3          # 试跑：只爬前3页
    python xianzhi_crawler.py --details-only         # 回填模式：给库里没正文的老记录补详情
"""

import argparse
import atexit
import html as html_mod
import json
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import requests
from bs4 import BeautifulSoup

BASE = "https://xz.aliyun.com"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
HEADERS = {"User-Agent": UA, "X-Requested-With": "XMLHttpRequest",
           "Referer": f"{BASE}/news"}
WAF_MARKERS = ("renderData", "acw_sc", "aliyun_waf")  # 详情页命中即判定为 WAF 挑战页
# 详情正文选择器：按先后尝试。若都取不到，用 --dump-html 存一份人工看结构后改这里。
DETAIL_SELECTORS = ["div.markdown-body", "div.article-content", "#content",
                    "div.content", "article", "div.news_content"]

RETRY, BACKOFF = 2, 2.0
DETAIL_ENGINE = "auto"  # auto=先requests后Playwright；playwright=跳过requests（先知已确认100%触发WAF，用这个省一半请求）


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def sleep_s(t: float):
    time.sleep(t)


def infer_record_type(url: str, source: str) -> str:
    """写入端质量门①：type 缺失时按 url/source 自动推断，杜绝空 type 入库。"""
    if "xz.aliyun.com" in url or source == "xianzhi":
        return "article"
    if source.startswith("rss:") or source in ("freebuf", "cnnvd-dynamic", "cnnvd-notice", "cnnvd-report"):
        return "rss_article"
    if "nvd.nist.gov/vuln/detail" in url or source in ("nvd", "kev"):
        return "cve"
    if source == "osv":
        return "advisory"
    return ""


# 反爬拦截页特征：正文命中即判定为风控页而非文章（FreeBuf 滑块页曾致 848 条污染；
# 2026-10-02 从 deep_fill 前移到写入端 Store.upsert，任何采集路径都进不来脏正文）
INTERCEPT_MARKS = ("请按住滑块", "拖动到最右边", "访问过于频繁", "环境异常",
                   "完成验证后", "拖动滑块完成验证", "captcha", "verify")


def is_intercept(md: str) -> bool:
    low = (md or "")[:800].lower()
    return any(m in low for m in INTERCEPT_MARKS)


# URL 规范化的去参白名单：只剥明确的跟踪参数，业务参数（如 zdziarski.com?p=13970）不动
_TRACKING_KEYS = {"spm", "fbclid", "gclid", "nsu"}


def norm_url(url: str) -> str:
    """URL 规范化（2026-10-02 补上原设计 §1.5 的缺口）：去 fragment、去跟踪参数、统一协议/域名小写。
    同一篇文章带不同 utm 参数的 URL 归一为一条，避免重复入库浪费下游 LLM 调用。"""
    try:
        s = urlsplit((url or "").strip())
    except ValueError:
        return (url or "").strip()
    host = (s.hostname or "").lower()
    netloc = f"{host}:{s.port}" if s.port and s.port not in (80, 443) else host
    q = [(k, v) for k, v in parse_qsl(s.query, keep_blank_values=True)
         if not (k.lower().startswith(("utm_", "share_")) or k.lower() in _TRACKING_KEYS)]
    return urlunsplit((s.scheme.lower(), netloc, s.path or "/", urlencode(q), ""))


class Store:
    """SQLite 索引：判重 + 断点。raw 原始件落盘一份，解析挂了可重跑不重爬。"""

    def __init__(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        self.raw_list = out_dir / "raw" / "xianzhi" / "list"
        self.raw_detail = out_dir / "raw" / "xianzhi" / "detail"
        self.raw_list.mkdir(parents=True, exist_ok=True)
        self.raw_detail.mkdir(parents=True, exist_ok=True)
        self.jsonl = out_dir / "xianzhi_records.jsonl"
        self.db = sqlite3.connect(out_dir / "index.sqlite")
        # 并发读写配置：多采集器并行 + deep_fill 同时写一库，WAL 读不阻塞写，锁冲突等待而非报错
        self.db.execute("PRAGMA busy_timeout=30000")   # 30s：多进程同库写（富化链 vs 采集器）排队而非报错
        try:
            self.db.execute("PRAGMA journal_mode=WAL")   # 首次转换需独占；并发时可能短暂失败，下次打开再转
        except sqlite3.OperationalError:
            pass
        self.db.execute("""CREATE TABLE IF NOT EXISTS records(
            id TEXT PRIMARY KEY, source TEXT, type TEXT DEFAULT '', url TEXT UNIQUE,
            url_norm TEXT DEFAULT '', title TEXT,
            summary TEXT DEFAULT '', category TEXT, tags TEXT DEFAULT '',
            publish_time TEXT, content_md TEXT,
            crawl_time TEXT, status TEXT)""")
        # 旧库迁移：补齐后加的列
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(records)").fetchall()}
        for col in ("type", "summary", "tags", "url_norm"):
            if col not in cols:
                self.db.execute(f"ALTER TABLE records ADD COLUMN {col} TEXT DEFAULT ''")
        # url_norm 存量回填（幂等：只补空值，2.9 万条秒级完成）
        empty = self.db.execute("SELECT url FROM records WHERE url_norm=''").fetchall()
        if empty:
            self.db.executemany("UPDATE records SET url_norm=? WHERE url=?",
                                [(norm_url(u), u) for (u,) in empty])
            self.db.commit()
        try:
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_records_url_norm ON records(url_norm)")
        except sqlite3.OperationalError:
            pass   # 库被其他进程持锁时跳过，下次打开再建
        self.db.commit()
        self._pending = 0
        atexit.register(self.flush)   # 正常退出时落盘批量提交的尾部

    def seen(self, url: str) -> bool:
        n = norm_url(url)
        return self.db.execute("SELECT 1 FROM records WHERE url=? OR url_norm=? LIMIT 1",
                               (url, n)).fetchone() is not None

    def flush(self):
        """把批量提交攒下的待写记录落盘（atexit 兜底调用；跨进程读前也可手动调）。"""
        if self._pending:
            self.db.commit()
            self._pending = 0

    def has_content(self, url: str) -> bool:
        row = self.db.execute("SELECT content_md FROM records WHERE url=?", (url,)).fetchone()
        return bool(row and row[0])

    def db_write(self, sql: str, params: tuple):
        """写库带锁重试（2026-10-13 实测修复）：多采集器并行写同一库时，rss 大批量
        插入可持锁 >30s，busy_timeout 不够——幂等写入重试零风险。所有写路径统一走这里。"""
        for _t in range(6):
            try:
                self.db.execute(sql, params)
                return
            except sqlite3.OperationalError as e:
                if "locked" not in str(e) or _t == 5:
                    raise
                time.sleep(2 * (_t + 1))

    def upsert(self, rec: dict, status: str):
        rec_type = rec.get("type") or infer_record_type(rec.get("url", ""), rec.get("source", ""))
        content_md = rec.get("content_md", "") or ""
        # 写入端质量门③：反爬拦截页（滑块/环境异常）混充正文 → 拒收，标 detail_failed 待冷却重抓
        gated = bool(content_md) and is_intercept(content_md)
        if gated:
            content_md, status = "", "detail_failed"
        # ⑧ 写锁重试：多采集器并行写同一库时，rss 大批量插入可持锁 >30s（2026-10-13 实测），
        # 统一走 db_write 的重试环——幂等写入重试零风险
        self.db_write("""INSERT INTO records(id,source,type,url,url_norm,title,summary,category,tags,
            publish_time,content_md,crawl_time,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(url) DO UPDATE SET
                url_norm=excluded.url_norm,
                content_md=CASE WHEN excluded.content_md='' THEN records.content_md
                                ELSE excluded.content_md END,
                type=excluded.type, summary=excluded.summary, tags=excluded.tags,
                status=CASE WHEN excluded.content_md='' THEN records.status
                            ELSE excluded.status END,
                crawl_time=excluded.crawl_time""",
                      (rec["id"], rec["source"], rec_type, rec["url"], norm_url(rec["url"]),
                       rec["title"], rec.get("summary", ""), rec.get("category", ""),
                       json.dumps(rec.get("tags", []), ensure_ascii=False),
                       rec.get("publish_time", ""), content_md,
                       rec["crawl_time"], status))
        # ⑦ 批量提交：64 条一 commit（backfill 提速一个量级）；崩溃最多丢 63 条，
        # 判重保证重爬不重复；正常退出由 atexit→flush() 兜底落盘
        self._pending += 1
        if self._pending >= 64:
            self.flush()
        if gated:   # 流水账与库保持一致，不落脏正文
            rec = {**rec, "content_md": ""}
        with open(self.jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def http_get(sess: requests.Session, url: str, *, headers=None, binary=False):
    """带重试与指数退避的 GET。返回 (resp|None)。"""
    for i in range(RETRY + 1):
        try:
            r = sess.get(url, headers=headers, timeout=15)
            if r.status_code == 200:
                return r
            print(f"  [warn] HTTP {r.status_code} {url}")
        except requests.RequestException as e:
            print(f"  [warn] {type(e).__name__} {url}")
        if i < RETRY:
            sleep_s(BACKOFF * (2 ** i))
    return None


def parse_list_payload(payload: dict, store: Store) -> tuple:
    """解析列表 JSON（fetch 与 parse 分离，便于单元测试）。返回 (记录列表, 是否全部已存在)。"""
    soup = BeautifulSoup(payload.get("data", ""), "html.parser")
    recs, all_seen = [], True
    for item in soup.select("div.news_item"):
        a = item.select_one("a.news_title")
        if not a:
            continue
        link = a.get("href", "").strip()
        title = a.get_text(strip=True)
        cat_el = item.select_one("a.cates_span")
        summary = item.select_one("div.news_word p")
        date_m = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", item.get_text(" ", strip=True))
        view_m = re.search(r"(\d+)\s*浏览", item.get_text(" ", strip=True))
        author = item.select_one("a.user-info span")
        rec = {
            "id": "xianzhi-" + link.rstrip("/").split("/")[-1],
            "source": "xianzhi",
            "type": "article",
            "url": link,
            "title": title,
            "summary": summary.get_text(strip=True) if summary else "",
            "category": cat_el.get_text(strip=True) if cat_el else "",
            "author": author.get_text(strip=True) if author else "",
            "publish_time": date_m.group(0) if date_m else "",
            "views": int(view_m.group(1)) if view_m else 0,
            "tags": ["xianzhi", cat_el.get_text(strip=True)] if cat_el else ["xianzhi"],
            "crawl_time": now_iso(),
            "content_md": "",
        }
        if not store.seen(link):
            all_seen = False
        recs.append(rec)
    return recs, all_seen


def max_page(payload_html: str) -> int:
    nums = [int(n) for n in re.findall(r"page=(\d+)", payload_html or "")]
    return max(nums) if nums else 1


def fetch_list_page(sess: requests.Session, page: int, category, store: Store) -> tuple:
    """拉一页列表 JSON，解析出记录 dict 列表 + 本页是否全部已存在。"""
    if category:
        url = f"{BASE}/news?isAjax=true&type=category&category={category}&cate_id=0&page={page}"
    else:
        url = f"{BASE}/news?isAjax=true&page={page}"
    r = http_get(sess, url, headers=HEADERS)
    if r is None:
        return [], True
    try:
        payload = json.loads(r.text)
    except json.JSONDecodeError:
        print(f"  [warn] 第{page}页不是JSON（可能触发WAF），已存原始件")
        (store.raw_list / f"page_{page}.bad").write_text(r.text, encoding="utf-8")
        return [], True
    (store.raw_list / f"page_{page}.json").write_text(r.text, encoding="utf-8")
    return parse_list_payload(payload, store)


def fetch_detail(sess: requests.Session, url: str, store: Store) -> str:
    """详情页：requests 直取；命中阿里云 WAF 挑战则切 Playwright 兜底。返回 markdown 正文。"""
    text = ""
    if DETAIL_ENGINE != "playwright":
        r = http_get(sess, url, headers={"User-Agent": UA, "Referer": BASE + "/"})
        text = r.text if r is not None else ""
    aid = url.rstrip("/").split("/")[-1]
    # Windows 文件名清洗（2026-10-16）：微信转载链接尾段 s?__biz=..&mid=.. 含 ? & =，
    # 直接落盘 OSError Errno 22——非法字符替换为 _ 并截断防超长路径
    aid = re.sub(r'[<>:"/\\|?*]', "_", aid)[:120]
    if DETAIL_ENGINE != "playwright" and not any(m in text for m in WAF_MARKERS):
        pass  # requests 直通（未触发 WAF），直接进解析
    else:
        if DETAIL_ENGINE != "playwright":
            print("  [info] 详情页触发阿里云WAF，切无头浏览器兜底")
        text = playwright_fetch(url)
    if not text:
        return ""
    (store.raw_detail / f"{aid}.html").write_text(text, encoding="utf-8")
    soup = BeautifulSoup(text, "html.parser")
    for sel in DETAIL_SELECTORS:
        node = soup.select_one(sel)
        if node and len(node.get_text(strip=True)) > 200:
            from markdownify import markdownify as md
            return md(str(node), heading_style="ATX", bullets="-")
    return ""


_PW = {"pw": None, "page": None}

MEDIA_RE = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|css)(\?|$)", re.I)


def harden_page(page):
    """T4 资源阻断：拦图片/字体/CSS，详情页加载提速 2-3 倍（正文抽取不需要它们）。"""
    page.route(MEDIA_RE, lambda route: route.abort())
    return page


def _pw_page():
    """复用同一个无头浏览器实例：490 条详情如果每条都启动/关闭浏览器会慢 5~10 倍。"""
    from playwright.sync_api import sync_playwright
    if _PW["page"] is None:
        _PW["pw"] = sync_playwright().start()
        browser = _PW["pw"].chromium.launch(headless=True)
        _PW["page"] = harden_page(browser.new_page(user_agent=UA))
    return _PW["page"]


def _pw_close():
    try:
        if _PW["page"] is not None:
            _PW["page"].context.browser.close()
    except Exception:
        pass
    try:
        if _PW["pw"] is not None:
            _PW["pw"].stop()
    except Exception:
        pass
    _PW["page"] = _PW["pw"] = None


def playwright_fetch(url: str) -> str:
    """无头浏览器取渲染后的 HTML（真实浏览器会自动过 WAF JS 挑战，不属于破解）。"""
    try:
        page = _pw_page()
    except ImportError:
        print("  [warn] 未安装 playwright，跳过该详情（uv add playwright && playwright install chromium）")
        return ""
    try:
        page.goto(url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(1200)
        return page.content()
    except Exception as e:
        print(f"  [warn] playwright失败: {type(e).__name__}，重建浏览器后重试一次")
        _pw_close()
        try:
            page = _pw_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(1200)
            return page.content()
        except Exception as e2:
            print(f"  [warn] 重试仍失败: {type(e2).__name__}")
            return ""


def main():
    ap = argparse.ArgumentParser(description="先知社区文章爬虫")
    ap.add_argument("--category", default="28",
                    help="分类ID：28=AI专栏(默认) 2=漏洞分析 14=WEB安全 15=移动安全；--all 时忽略")
    ap.add_argument("--all", action="store_true", help="全站全部分类")
    ap.add_argument("--list-only", action="store_true", help="只抓列表元数据，不进详情")
    ap.add_argument("--details-only", action="store_true", help="回填模式：给库里没正文的记录补详情")
    ap.add_argument("--full", action="store_true", help="忽略增量判断，爬完全部页")
    ap.add_argument("--max-pages", type=int, default=0, help="最多爬几页（0=不限制），试跑用")
    ap.add_argument("--sleep", type=float, default=2.0, help="列表页间隔秒数")
    ap.add_argument("--detail-engine", default="auto", choices=["auto", "playwright"],
                    help="auto=先requests再Playwright兜底；playwright=详情直接走无头浏览器（先知全量跑用这个）")
    ap.add_argument("--out-dir", default="./data", help="数据目录（默认 ./data）")
    args = ap.parse_args()

    global DETAIL_ENGINE
    DETAIL_ENGINE = args.detail_engine

    store = Store(Path(args.out_dir))
    sess = requests.Session()
    category = None if args.all else args.category
    label = "全站" if args.all else f"分类{category}"

    if args.details_only:  # 回填：不碰列表，只补正文
        rows = store.db.execute(
            "SELECT url, title FROM records WHERE content_md IS NULL OR content_md=''").fetchall()
        print(f"回填模式：待补正文 {len(rows)} 条")
        for i, (url, title) in enumerate(rows, 1):
            print(f"[{i}/{len(rows)}] {title[:30]}")
            md = fetch_detail(sess, url, store)
            store.db_write("UPDATE records SET content_md=?, status=? WHERE url=?",
                          (md, "enriched" if md else "detail_failed", url))
            store.db.commit()
            sleep_s(1.5)
        print("回填完成")
        return

    # ---- 阶段一：列表翻页 ----
    page, total_new, stop_early = 1, 0, False
    last_page = None
    while True:
        recs, all_seen = fetch_list_page(sess, page, category, store)
        if not recs:
            print(f"第{page}页无数据，停止")
            break
        new = [r for r in recs if not store.seen(r["url"])]
        total_new += len(new)
        print(f"[{label}] 第{page}/{last_page or '?'}页: {len(recs)}条, 新{len(new)}条")
        for r in new:
            store.upsert(r, "listed")
        if last_page is None:
            # 翻页信息在同一响应的 pagination 字段里，重新读原始件取最大页码
            raw = (store.raw_list / f"page_{page}.json")
            if raw.exists():
                try:
                    last_page = max_page(json.loads(raw.read_text(encoding="utf-8")).get("pagination", ""))
                    print(f"  检测到最大页码: {last_page}")
                except Exception:
                    last_page = 1
        if all_seen and not args.full:
            print("  本页全部已存在，增量结束（--full 可强制全量）")
            break
        if args.max_pages and page >= args.max_pages:
            print("  达到 --max-pages，停止")
            stop_early = True
            break
        if last_page and page >= last_page:
            break
        page += 1
        sleep_s(args.sleep)

    print(f"列表完成：新增 {total_new} 条")

    # ---- 阶段二：详情（--max-pages 只限制列表页数，不影响详情回填） ----
    if args.list_only:
        return
    rows = store.db.execute("SELECT url, title FROM records WHERE content_md IS NULL OR content_md=''").fetchall()
    print(f"待抓正文 {len(rows)} 条（限速进行，可 Ctrl-C 中断，已抓的不会重复）")
    for i, (url, title) in enumerate(rows, 1):
        print(f"[{i}/{len(rows)}] {title[:34]}")
        md = fetch_detail(sess, url, store)
        store.db_write("UPDATE records SET content_md=?, status=? WHERE url=?",
                      (md, "enriched" if md else "detail_failed", url))
        store.db.commit()
        sleep_s(1.5)
    print("完成。记录见 xianzhi_records.jsonl，索引见 index.sqlite")


if __name__ == "__main__":
    import atexit
    atexit.register(_pw_close)
    main()

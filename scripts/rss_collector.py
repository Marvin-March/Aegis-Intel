#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSS 广撒网采集器（浅抓）—— 阶段一 A2，参照 yarb 模式

定位：与 xianzhi_crawler.py（深抓全文）互补——本脚本对几百个 RSS 源只抓
"标题+链接+摘要"（快、礼貌、覆盖面大），命中关键词的才入库；重点源再由
深抓器补正文。共用统一记录格式与 SQLite 判重（source+url 唯一）。

用法（都在项目根目录跑）：
    uv run python scripts/rss_collector.py                    # 按 config.json 全量
    uv run python scripts/rss_collector.py --lookback 7      # 回填一周
    uv run python scripts/rss_collector.py --max-feeds 12    # 试跑：只测12个源
    uv run python scripts/rss_collector.py --no-digest       # 不生成每日简报

配置在 ../config.json（源 OPML / include / exclude / 回看天数 / 并发 / 代理）。
产出：记录进 data/index.sqlite + data/xianzhi_records.jsonl（同库同账本），
每日简报进 data/daily/YYYY-MM-DD.md。
"""

import argparse
import concurrent.futures
import hashlib
import html as html_mod
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import feedparser
import listparser
import requests

from xianzhi_crawler import Store, UA, now_iso

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def clean(text: str, limit: int = 500) -> str:
    """HTML 标签剥离 + 实体还原（&nbsp; 等），写入端质量门的一部分。"""
    return WS_RE.sub(" ", TAG_RE.sub(" ", html_mod.unescape(text or ""))).strip()[:limit]


def load_config(path: Path) -> dict:
    cfg = {
        "opml": [], "include": [], "exclude": [], "deep_feeds": [],
        "lookback_days": 1, "workers": 20, "timeout": 10, "proxy": "",
    }
    if path.exists():
        cfg.update(json.loads(path.read_text(encoding="utf-8")))
    return cfg


def is_deep_feed(url: str, deep_feeds: list) -> bool:
    """优选源判定：deep_feeds 列表里的 feed 全收不做关键词过滤（AI 判定交给 LLM gate）。"""
    return any(d and (d in url or url in d) for d in deep_feeds)


def load_feeds(opml_paths: list, root: Path) -> list:
    """解析 OPML 文件并按 host 去重（yarb 的源清单有大量重叠）。"""
    feeds, seen = [], set()
    for p in opml_paths:
        fp = p if Path(p).is_absolute() else root / p
        if not fp.exists():
            print(f"[warn] OPML 不存在: {fp}")
            continue
        try:
            doc = listparser.parse(fp.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            print(f"[warn] OPML 解析失败 {fp}: {e}")
            continue
        for feed in doc.feeds:
            url = (feed.url or "").strip().rstrip("/")
            if not url.startswith("http"):
                continue
            host = url.split("://")[-1].replace("www.", "")
            if host not in seen:
                seen.add(host)
                feeds.append(url)
    return feeds


def entry_date(e):
    for k in ("published_parsed", "updated_parsed"):
        d = e.get(k)
        if d:
            return datetime(*d[:6])
    return None


def match_keywords(title: str, include: list, exclude: list):
    """返回命中的 include 关键词（include 为空=全收），被 exclude 命中则拒绝。"""
    if any(x in title for x in exclude):
        return None
    if not include:
        return ""
    for kw in include:
        if kw in title:
            return kw
    return None


def fetch_once(url: str, timeout: int, proxy: str, etag: str = "", last_mod: str = ""):
    """T3 条件请求：带 If-None-Match/If-Modified-Since，304=源未更新直接跳过解析。"""
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {"User-Agent": UA}
    if etag:
        headers["If-None-Match"] = etag
    if last_mod:
        headers["If-Modified-Since"] = last_mod
    r = requests.get(url, timeout=timeout, headers=headers, proxies=proxies)
    if r.status_code == 304:
        return None, r.headers.get("ETag", etag), r.headers.get("Last-Modified", last_mod)
    r.raise_for_status()
    return r.content, r.headers.get("ETag", ""), r.headers.get("Last-Modified", "")


def parse_feed(url: str, cfg: dict, deep: bool = False, feed_state: dict = None) -> tuple:
    """抓一个 RSS 源，返回 (feed名, [记录], new_etag, new_lastmod)。单源失败返回空。"""
    title, recs = url.split("//")[-1].split("/")[0], []
    new_etag, new_lm = "", ""
    try:
        st = (feed_state or {}).get(url, {})
        content, new_etag, new_lm = fetch_once(url, cfg["timeout"], cfg.get("proxy", ""),
                                               etag=st.get("etag", ""), last_mod=st.get("last_modified", ""))
        if content is None:                       # 304：未更新
            return title, [], new_etag, new_lm, "unchanged"
        d = feedparser.parse(content)
        if d.feed.get("title"):
            title = d.feed.title
        cutoff = datetime.now() - timedelta(days=int(cfg.get("lookback_days", 1)))
        for e in d.entries:
            dt = entry_date(e)
            if dt and dt < cutoff:          # 有日期且超窗 → 跳过；无日期 → 收（判重兜底）
                continue
            t = e.get("title", "").strip()
            if not t:
                continue
            # 3.1 deep_feeds：优选源不做关键词过滤，全收（AI 判定交给 LLM gate）
            kw = match_keywords(t, cfg.get("include", []), cfg.get("exclude", [])) \
                if not deep else ""
            if kw is None:
                continue
            link = (e.get("link") or "").strip()
            if not link.startswith("http"):
                continue
            # 数据质量优化：部分 feed 的 description 自带全文——超 800 字直接当正文入库，
            # 省一次详情页抓取（未来增量生效）
            full = clean(e.get("description") or e.get("summary") or "", limit=10 ** 9)
            tags = ["rss"] + ([kw] if kw else []) + (["deep_feed"] if deep else [])
            recs.append({
                "id": "rss-" + hashlib.sha1(link.encode()).hexdigest()[:16],
                "source": f"rss:{title[:60]}",
                "type": "rss_article",
                "url": link,
                "title": t,
                "summary": clean(e.get("description") or e.get("summary") or ""),
                "publish_time": dt.strftime("%Y-%m-%d %H:%M") if dt else "",
                "tags": tags,
                "crawl_time": now_iso(),
                "content_md": full if len(full) >= 800 else "",
            })
    except Exception as e:
        print(f"  [skip] {title}: {type(e).__name__}")
        return "", [], "", "failed"   # 失败源返回空名，主流程据此不计入可用
    return title, recs, new_etag, new_lm, "ok"


def write_digest(new_recs: list, out_dir: Path):
    """每日简报：按来源分组的新文章清单（抄 yarb 的 today.md 形态）。"""
    if not new_recs:
        return
    day = datetime.now().strftime("%Y-%m-%d")
    digest_dir = out_dir / "daily"
    digest_dir.mkdir(parents=True, exist_ok=True)
    groups = {}
    for r in new_recs:
        groups.setdefault(r["source"], []).append(r)
    lines = [f"# 每日 AI 安全资讯（{day}）", "", f"新增 {len(new_recs)} 条 / {len(groups)} 个来源", ""]
    for src in sorted(groups):
        lines.append(f"## {src}")
        for r in groups[src]:
            lines.append(f"- [{r['title']}]({r['url']})")
        lines.append("")
    (digest_dir / f"{day}.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"简报: {digest_dir / (day + '.md')}")


def main():
    ap = argparse.ArgumentParser(description="RSS 广撒网采集器（浅抓）")
    ap.add_argument("--config", default="config.json", help="配置文件（默认项目根 config.json）")
    ap.add_argument("--lookback", type=int, default=0, help="覆盖回看天数（0=用配置值）")
    ap.add_argument("--max-feeds", type=int, default=0, help="只测前 N 个源（试跑用）")
    ap.add_argument("--out-dir", default="./data", help="数据目录")
    ap.add_argument("--no-digest", action="store_true", help="不生成每日简报")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    cfg = load_config(root / args.config if not Path(args.config).is_absolute() else Path(args.config))
    if args.lookback:
        cfg["lookback_days"] = args.lookback

    feeds = load_feeds(cfg.get("opml", []), root)
    if args.max_feeds:
        feeds = feeds[:args.max_feeds]
    print(f"订阅源 {len(feeds)} 个，回看 {cfg['lookback_days']} 天，并发 {cfg['workers']}，深抓优选源 {len(cfg.get('deep_feeds', []))} 个")

    store = Store(Path(args.out_dir))
    # T3 条件请求的 etag 持久化：feed_state(feed_url PK, etag, last_modified, last_check)
    store.db.execute("""CREATE TABLE IF NOT EXISTS feed_state(
        feed_url TEXT PRIMARY KEY, etag TEXT, last_modified TEXT, last_check TEXT)""")
    store.db.commit()
    fstate = {u: {"etag": e or "", "last_modified": lm or ""} for u, e, lm in
              store.db.execute("SELECT feed_url, etag, last_modified FROM feed_state")}

    ok, dead, new_recs, unchanged = 0, 0, [], 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=int(cfg["workers"])) as ex:
        futs = {ex.submit(parse_feed, u, cfg, is_deep_feed(u, cfg.get("deep_feeds", [])), fstate): u
                for u in feeds}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            if done % 100 == 0:
                print(f"  进度 {done}/{len(feeds)}")
            feed_url = futs[fut]
            try:
                title, recs, netag, nelm, status = fut.result()
            except Exception:
                title, recs, netag, nelm, status = "", [], "", "", "failed"
            if status == "unchanged":
                unchanged += 1
                store.db.execute("""INSERT INTO feed_state(feed_url,etag,last_modified,last_check)
                    VALUES(?,?,?,?) ON CONFLICT(feed_url) DO UPDATE SET last_check=excluded.last_check""",
                                 (feed_url, netag, nelm, now_iso()))
                continue
            if title:
                ok += 1
                store.db.execute("""INSERT INTO feed_state(feed_url,etag,last_modified,last_check)
                    VALUES(?,?,?,?) ON CONFLICT(feed_url) DO UPDATE SET etag=excluded.etag,
                    last_modified=excluded.last_modified, last_check=excluded.last_check""",
                                 (feed_url, netag, nelm, now_iso()))
            for r in recs:
                if not store.seen(r["url"]):
                    store.upsert(r, "listed")
                    new_recs.append(r)
    store.db.commit()

    print(f"完成：可用源 {ok}/{len(feeds)}（304 未更新 {unchanged}），新增记录 {len(new_recs)} 条")
    if not args.no_digest:
        write_digest(new_recs, Path(args.out_dir))


if __name__ == "__main__":
    main()

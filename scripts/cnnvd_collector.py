#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CNNVD「国家人工智能安全漏洞库」(AIVD) 采集器 —— 阶段一采集器的权威中文源补充

原理（为什么这么写）：
1. AIVD 专题页 https://www.cnnvd.org.cn/frontend/aiVulnerabilityDatabase 由前端 JS
   调用四个公开接口取数：ai/searchVul（AI 漏洞，total≈6353）、ai/searchDynamic（动态）、
   ai/searchNotice（预警）、ai/searchReport（报告）。
2. 接口带签名（x-appid/x-timestamp/x-nonce/x-sign，先 POST /tourist/sign 换 token），
   直连会被 WAF 405/挂起——**不逆向签名**，用 Playwright 打开真实页面，让站点自己的
   JS 完成握手和签名，脚本只拦截这四个接口的响应。
3. 已知约束：公开 UI 只露出最新 10 条漏洞 + 动态/报告各 5 条（无翻页入口）。
   CNNVD 约每天凌晨批量插入 10-30 条 → **每日跑一次正好覆盖增量**；6353 条历史回填
   需要等 UI 出现翻页入口或其他通道（已在文档注明）。
4. 产出：searchVul → cve 记录 + vuln_meta（中文描述！ai_related=1，severity 映射）；
   Dynamic/Notice/Report → article 记录。

用法：
    uv run python scripts/cnnvd_collector.py                  # 抓最新一批（增量靠判重）
    uv run python scripts/cnnvd_collector.py --headed         # 无头被 WAF 卡住时用有头模式
    uv run python scripts/cnnvd_collector.py --wait 90        # 握手慢时加大等待
"""

import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

from xianzhi_crawler import Store, now_iso, harden_page

BASE = "https://www.cnnvd.org.cn"
PAGE_URL = f"{BASE}/frontend/aiVulnerabilityDatabase"
APIS = {"vul": "/cnnvdweb/ai/searchVul", "dynamic": "/cnnvdweb/ai/searchDynamic",
        "notice": "/cnnvdweb/ai/searchNotice", "report": "/cnnvdweb/ai/searchReport"}
LEVEL_MAP = {"超危": "critical", "高危": "high", "中危": "medium", "低危": "low"}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")


def collect_responses(page, wait_s: int) -> dict:
    """打开专题页并等待四个接口的响应（WAF 握手由页面 JS 完成）。返回 {key: dict}。"""
    got = {}

    def on_response(resp):
        for key, path in APIS.items():
            if path in resp.url and resp.status == 200:
                try:
                    body = resp.json()
                    if body.get("success"):
                        got[key] = body.get("data") or {}
                except Exception:
                    pass

    page.on("response", on_response)
    page.goto(PAGE_URL, wait_until="domcontentloaded", timeout=60000)
    deadline = time.time() + wait_s
    while time.time() < deadline and "vul" not in got:
        page.wait_for_timeout(2000)
    page.wait_for_timeout(3000)   # 给 dynamic/notice/report 一点余量
    page.remove_listener("response", on_response)
    return got


def vul_records(entries: list) -> tuple:
    recs, metas = [], []
    for v in entries:
        cid = (v.get("cveId") or "").strip()
        cnnvd_id = v.get("cnnvdId") or ""
        vul_id = v.get("id") or ""
        url = f"{BASE}/frontend/detail?vulId={vul_id}"
        detail = v.get("vulDetail") or v.get("vulDesc") or ""
        level = v.get("vulLevel", "")
        sev = LEVEL_MAP.get(level, "")
        patch = v.get("officialPatchLink") or ""
        nvd = f"https://nvd.nist.gov/vuln/detail/{cid}" if cid else ""
        rec = {
            "id": ("cve-" + cid) if cid else "cnnvd-" + cnnvd_id,
            "source": "cnnvd",
            "type": "cve" if cid else "advisory",
            "url": url,
            "title": f"{v.get('vulName', '')}（{level}）" if level else v.get("vulName", ""),
            "summary": (v.get("vulDesc") or "")[:1200],
            "publish_time": v.get("publishDate", ""),
            "tags": ["cnnvd", "AIVD", "CNNVD:" + cnnvd_id, level]
                    + ([f"CVE:{cid}"] if cid else [])
                    + ([f"修复:{v.get('fixStatus')}"] if v.get("fixStatus") else []),
            "crawl_time": now_iso(),
            "content_md": (f"{detail}\n\n"
                           f"- CNNVD 编号: {cnnvd_id}\n- 危害等级: {level}（{sev}）\n"
                           f"- 厂商/产品: {v.get('vendorName', '')} / {v.get('productName', '')}\n"
                           f"- 漏洞类型: {v.get('mappedVulType', '')}（{v.get('vulType', '')}）\n"
                           f"- 修复状态: {v.get('fixStatus', '')}\n"
                           f"- 发布日期: {v.get('publishDate', '')}（CNNVD 入库: {v.get('insertTime', '')}）\n"
                           + (f"- 官方补丁: {patch}\n" if patch else "")
                           + (f"- NVD 关联: {nvd}\n" if nvd else "")),
        }
        recs.append(rec)
        metas.append({"cve_id": cid or cnnvd_id, "cvss": None,
                      "severity": sev or None, "kev": 0, "epss": None, "cpes": "[]",
                      "ai_related": 1,   # AIVD 本身就是 AI 漏洞库，条目天然 AI 相关
                      "matched": json.dumps(["CNNVD-AIVD"]),
                      "updated_at": now_iso()})
    return recs, metas


def article_records(entries: list, kind: str) -> list:
    recs = []
    for e in entries:
        eid = e.get("id", "")
        recs.append({
            "id": "article-" + hashlib_slug(eid),
            "source": f"cnnvd-{kind}",
            "type": "article",
            "url": f"{BASE}/cnnvdweb/ai/{kind}/{eid}",   # 标识 URI（详情页为 SPA 无独立地址）
            "title": e.get("title", ""),
            "summary": (e.get("content") or "")[:800],
            "publish_time": e.get("publish_time", ""),
            "tags": ["cnnvd", "AIVD", kind],
            "crawl_time": now_iso(),
            "content_md": (e.get("content") or "").strip(),
        })
    return recs


def hashlib_slug(s: str) -> str:
    import hashlib
    return hashlib.sha1(s.encode()).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser(description="CNNVD AIVD 采集器")
    ap.add_argument("--wait", type=int, default=75, help="等待 WAF 握手+数据的秒数")
    ap.add_argument("--headed", action="store_true", help="有头模式（无头被 WAF 卡住时用）")
    ap.add_argument("--out-dir", default="./data")
    args = ap.parse_args()

    store = Store(Path(args.out_dir))
    store.db.execute("""CREATE TABLE IF NOT EXISTS vuln_meta(
        cve_id TEXT PRIMARY KEY, cvss REAL, severity TEXT, kev INTEGER, epss TEXT,
        cpes TEXT, ai_related INTEGER, matched TEXT, updated_at TEXT)""")
    store.db.commit()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed)
        page = harden_page(browser.new_page(user_agent=UA, viewport={"width": 1440, "height": 900}))
        try:
            got = collect_responses(page, args.wait)
        except Exception as e:
            # 站点不可达（ERR_CONNECTION_RESET 等）按设计优雅放弃：不视为失败，
            # 等下一日批次再试（README 既定口径）
            print(f"[cnnvd] 站点不可达（{type(e).__name__}），本轮跳过，等下日批次")
            browser.close()
            return
        # 首次加载握手常卡住（实测），刷新一次即过
        if "vul" not in got:
            print("[cnnvd] 首次加载握手未完成，刷新重试…")
            try:
                page.reload(wait_until="domcontentloaded", timeout=60000)
            except Exception as e:
                print(f"[cnnvd] reload 超时（站点限流/慢），本轮放弃: {type(e).__name__}")
                browser.close()
                return got
            got = collect_responses(page, args.wait)
        browser.close()

    if not got:
        print("[cnnvd] 未捕获任何接口响应（WAF 或网络问题），可试 --headed --wait 120")
        return

    n_cve, n_art, n_merged = 0, 0, 0
    if "vul" in got:
        recs, metas = vul_records(got["vul"].get("records", []))
        for r, m in zip(recs, metas):
            existing = store.db.execute(
                "SELECT content_md FROM records WHERE id=?", (r["id"],)).fetchone()
            if existing:
                # 多源合并：同一条 CVE 已在库（如 NVD 来源）→ 追加 CNNVD 补充节，不建新行
                if "CNNVD 补充" not in (existing[0] or ""):
                    extra = "\n".join(l for l in r["content_md"].splitlines() if l.startswith(
                        ("- CNNVD 编号:", "- 危害等级:", "- 修复状态:", "- 官方补丁:", "- 发布日期:")))
                    store.db.execute("UPDATE records SET content_md=?, crawl_time=? WHERE id=?",
                                     (existing[0] + f"\n\n### CNNVD 补充\n{extra}", now_iso(), r["id"]))
                n_merged += 1
            elif not store.seen(r["url"]):
                store.upsert(r, "listed")
                n_cve += 1
        for m in metas:
            store.db.execute("""INSERT INTO vuln_meta(cve_id,cvss,severity,kev,epss,cpes,ai_related,matched,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET severity=COALESCE(excluded.severity, severity),
                ai_related=1, matched=excluded.matched, updated_at=excluded.updated_at""",
                (m["cve_id"], m["cvss"], m["severity"], m["kev"], m["epss"],
                 m["cpes"], m["ai_related"], m["matched"], m["updated_at"]))
        store.db.commit()
        print(f"[cnnvd] searchVul 库内总量 {got['vul'].get('total')} 条（新增 {n_cve}，合并补充 {n_merged}）")
    for key in ("dynamic", "notice", "report"):
        if key in got:
            for r in article_records(got[key].get("records", []), key):
                if not store.seen(r["url"]):
                    store.upsert(r, "listed")
                    n_art += 1
    print(f"[cnnvd] 文章类新增 {n_art} 条，完成")


if __name__ == "__main__":
    main()

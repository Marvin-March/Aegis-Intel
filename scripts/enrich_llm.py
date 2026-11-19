#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
enrich_llm.py —— 富化管线 L3：LLM 语义富化（中文摘要/攻击类型/实体/子分类）

范围（刻意砍小）：AI 库 CVE 1,233 条 + 有正文文章 1,425 篇；非 AI 的 2.2 万条 CVE 不富化。
预检：每条输出里的 CVE 编号必须已存在于库中，否则标记 fabrication（防编造——设计文档铁律 3）。

用法：
    uv run python scripts/enrich_llm.py --kind cve     --limit 10   # 试跑
    uv run python scripts/enrich_llm.py --kind all                  # CVE→文章 顺序全量
凭据：.env 的 GLM_API_KEY（默认）或 DEEPSEEK_API_KEY（--provider deepseek）。
"""

import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).parent))
from llm_review_weak import PROVIDERS, load_dotenv

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
ATTACK_TYPES = ["RCE", "权限提升", "信息泄露", "SSRF", "反序列化", "认证绕过",
                "拒绝服务", "路径遍历", "SQL注入", "XSS", "供应链", "其他"]
SUBCATS = ["LLM漏洞与攻防", "提示词注入", "越狱与滥用", "Agent安全", "MCP/工具链安全",
           "模型供应链投毒", "对抗样本", "数据投毒与隐私", "AI应用安全", "AI辅助安全研究",
           "AI组件基础设施漏洞"]

SYSTEM = ("你是 AI 安全情报分析引擎，负责任务型文本富化加工。铁律："
          "1. 只依据输入文本判断和提取，禁止用自己的知识补充事实；"
          "2. 文本中没有的信息，对应字段输出 null 或空数组，不要猜测；"
          "3. 输出必须是合法 JSON，不输出 JSON 以外的任何内容。")

PROMPT_CVE = """【任务】把下面这条 CVE 漏洞数据加工成中文情报。

【数据】
CVE 编号：{cve_id}
CVSS：{cvss}（{severity}）
受影响组件：{component}
描述：{desc}
KEV 在野利用：{kev}    EPSS 利用概率：{epss}

【字段定义】
- summary_zh: 120 字内中文摘要：什么漏洞、影响什么、攻击后果
- attack_type: 从 ["RCE","权限提升","信息泄露","SSRF","反序列化","认证绕过",
  "拒绝服务","路径遍历","SQL注入","XSS","供应链","其他"] 选一个
- ai_subcategory: 数组，从 ["LLM漏洞与攻防","提示词注入","越狱与滥用","Agent安全",
  "MCP/工具链安全","模型供应链投毒","对抗样本","数据投毒与隐私","AI应用安全",
  "AI组件基础设施漏洞"] 中选（可多选）
- exploitability_note: KEV/EPSS/描述中体现的可利用性要点，无则 null
- remediation_zh: 修复建议（仅基于描述中的官方信息，无则 null）

【输出】仅 JSON。"""

PROMPT_ARTICLE = """【任务】对下面这篇安全文章做结构化富化。

【文章】
标题：{title}
来源：{source}
正文：{content}

【字段定义】
- ai_related: 布尔。是否与"AI 系统安全"相关。仅用 AI 辅助安全分析、纯 AI 产品新闻、
  与 AI 无关的传统安全内容 → false。
- ai_subcategory: 数组，从 ["LLM漏洞与攻防","提示词注入","越狱与滥用","Agent安全",
  "MCP/工具链安全","模型供应链投毒","对抗样本","数据投毒与隐私","AI应用安全",
  "AI辅助安全研究","AI组件基础设施漏洞"] 中选（可多选，无关则 []）
- summary_zh: 200 字内中文摘要，突出：什么漏洞/攻击、影响什么、怎么防。
- entities: {{"cves": ["正文中出现的 CVE 编号"],
             "components": ["软件组件/产品"],
             "vendors": ["厂商"],
             "attack_techniques": ["攻击手法中文短语"],
             "defenses": ["文中提到的防御措施"]}}
- exploitation: 攻击链或利用条件简述，无则 null
- remediation: 修复建议简述，无则 null

【输出】仅 JSON。"""


def ask_llm(base, model, key, user_prompt, timeout):
    """一次调用，从回复里抠 JSON。失败返回 None。
    429 限流时自动降级 glm-4-flash（两档模型限流池独立，2026-10-14 实测：4.5-flash
    被 429 时 4-flash 仍 1.1s 可用）。glm 降级仅对 GLM base 有意义——其他平台传
    glm-4-flash 模型名只会 404 白白重试（2026-10-16 切 DeepSeek 官方时修正）。"""
    fallback = ["glm-4-flash"] if ("bigmodel" in base and model != "glm-4-flash") else []
    models = [model] + fallback
    for m in models:
        for attempt in range(3):
            try:
                r = requests.post(f"{base}/chat/completions",
                                  headers={"Authorization": f"Bearer {key}"},
                                  json={"model": m, "temperature": 0.1,
                                        "messages": [{"role": "system", "content": SYSTEM},
                                                     {"role": "user", "content": user_prompt}]},
                                  timeout=timeout)
                if r.status_code == 429 and m != "glm-4-flash":
                    print(f"    {m} 429 限流，降级 glm-4-flash")
                    break                      # 不空等重试，直接换稳定档
                if r.status_code == 429:
                    time.sleep(5 * (attempt + 1))
                    continue
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"]
                m2 = re.search(r"\{.*\}", text, re.S)
                if m2:
                    return json.loads(m2.group())
                return None
            except (requests.RequestException, KeyError, ValueError) as e:
                print(f"    {type(e).__name__}，重试 {attempt + 1}/3")
                time.sleep(3 * (attempt + 1))
    return None


def fabricate_check(data, kind, db):
    """防编造铁律：LLM 给出的 CVE 编号必须真实存在于库中。返回 (伪造数, 总数)。"""
    ids = []
    if kind == "article":
        ids = (data.get("entities") or {}).get("cves") or []
    ids = [i for i in ids if isinstance(i, str)]
    if not ids:
        return 0, 0
    known = {r[0] for r in db.execute(
        "SELECT id FROM records WHERE id IN (%s)" % ",".join("?" * len(ids)),
        ["cve-" + i.upper() for i in ids])}
    bad = [i for i in ids if ("cve-" + i.upper()) not in known]
    return len(bad), len(ids)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default="cve", choices=["cve", "article", "all"])
    ap.add_argument("--provider", default="glm", choices=list(PROVIDERS))
    ap.add_argument("--api-key", default="")
    ap.add_argument("--model", default="")
    ap.add_argument("--db", default=str(ROOT / "data" / "index.sqlite"))
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=6, help="LLM 调用并发数（免费档建议 ≤8）")
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    cfg = PROVIDERS[args.provider]
    key = args.api_key or __import__("os").environ.get(cfg["env"], "") or load_dotenv().get(cfg["env"], "")
    if not key:
        sys.exit(f"未找到 {cfg['env']}：--api-key、环境变量或写入项目根 .env")
    model = args.model or cfg["model"]
    db = sqlite3.connect(args.db)
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")

    kinds = ["cve", "article"] if args.kind == "all" else [args.kind]
    for kind in kinds:
        run_kind(kind, db, cfg, model, key, args)
    db.close()


def run_kind(kind, db, cfg, model, key, args):
    now = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if kind == "cve":
        cols = {r[1] for r in db.execute("PRAGMA table_info(vuln_meta)").fetchall()}
        if "enrich_json" not in cols:
            db.execute("ALTER TABLE vuln_meta ADD COLUMN enrich_json TEXT DEFAULT ''")
        if "summary_zh" not in cols:
            db.execute("ALTER TABLE vuln_meta ADD COLUMN summary_zh TEXT DEFAULT ''")
        db.commit()
        rows = db.execute("""SELECT v.cve_id, r.summary, v.cvss, v.severity,
              COALESCE(NULLIF(v.affected_component,''),'未知'), v.kev, v.epss
            FROM vuln_meta v JOIN records r ON r.id='cve-'||v.cve_id
            WHERE v.ai_related=1 AND (v.enrich_json IS NULL OR v.enrich_json='')
            ORDER BY v.cve_id""").fetchall()
        print(f"[cve] 待富化 {len(rows)} 条（模型 {model}）")
    else:
        db.execute("""CREATE TABLE IF NOT EXISTS article_enrich(
            url TEXT PRIMARY KEY, summary_zh TEXT, entities TEXT, subcategory TEXT,
            exploitation TEXT, remediation TEXT, fabrications INTEGER DEFAULT 0,
            model TEXT, created_at TEXT)""")
        db.commit()
        rows = db.execute("""SELECT r.url, r.title, r.source, r.content_md
            FROM records r LEFT JOIN article_enrich ae ON ae.url = r.url
            WHERE r.type IN ('article','rss_article') AND length(r.content_md)>=300
            AND ae.url IS NULL""").fetchall()
        print(f"[article] 待富化 {len(rows)} 篇（模型 {model}）")
    if args.limit:
        rows = rows[:args.limit]

    stats = {"ok": 0, "fail": 0, "fab": 0}
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def build_user(row):
        if kind == "cve":
            cve_id, desc, cvss, sev, comp, kev, epss = row
            return PROMPT_CVE.format(cve_id=cve_id, cvss=cvss or "-", severity=sev or "-",
                                     component=comp, desc=(desc or "")[:1200],
                                     kev="是" if kev else "否", epss=epss or "-")
        url, title, source, content = row
        return PROMPT_ARTICLE.format(title=title, source=source, content=(content or "")[:6000])

    # 并发版：LLM 调用是网络 IO，线程池并发把吞吐提升 N 倍；DB 写全部在主线程串行
    conc = max(1, args.concurrency)
    with ThreadPoolExecutor(max_workers=conc) as pool:
        futs = {pool.submit(ask_llm, cfg["base"], model, key, build_user(row), args.timeout): row
                for row in rows}
        for i, fut in enumerate(as_completed(futs), 1):
            row = futs[fut]
            data = fut.result()
            if data is None:
                stats["fail"] += 1
            elif kind == "cve":
                cve_id = row[0]
                data["enrich_meta"] = {"model": model, "enriched_at": now}
                db.execute("UPDATE vuln_meta SET enrich_json=?, summary_zh=? WHERE cve_id=?",
                           (json.dumps(data, ensure_ascii=False), data.get("summary_zh") or "", cve_id))
                stats["ok"] += 1
            else:
                url = row[0]
                fab, tot = fabricate_check(data, "article", db)
                stats["fab"] += fab
                db.execute("""INSERT OR REPLACE INTO article_enrich
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                           (url, data.get("summary_zh") or "",
                            json.dumps(data.get("entities") or {}, ensure_ascii=False),
                            json.dumps(data.get("ai_subcategory") or [], ensure_ascii=False),
                            str(data.get("exploitation")), str(data.get("remediation")),
                            fab, model, now))
                stats["ok"] += 1
            if i % 10 == 0:
                db.commit()
            if i % 20 == 0 or i == len(rows):
                print(f"  进度 {i}/{len(rows)}  ok={stats['ok']} fail={stats['fail']} 伪造CVE={stats['fab']}", flush=True)
    db.commit()
    print(f"[{kind}] 完成：ok={stats['ok']} fail={stats['fail']} 伪造CVE={stats['fab']}")


if __name__ == "__main__":
    main()

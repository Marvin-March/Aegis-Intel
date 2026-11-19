# -*- coding: utf-8 -*-
"""版本区间富化补丁（2026-10-16，"定位受影响资产与组件"直接相关）。

范围：ai_related=1 且 cvss>=9 的高危漏洞（默认；--all 跑全部 AI 漏洞）。
做法：summary_zh + 原始描述 → DeepSeek 抽取受影响版本区间与修复版本 → 回填
vuln_meta.affected_versions（格式："影响 <=1.82.4；升级 1.84.0 修复"）。

防幻觉：①LLM 输出 JSON，known=false（文本无版本信息）则留空；
      ②抽取到的版本号字符串必须在原文/摘要中出现（fabricate 校验），否则丢弃。
幂等：affected_versions 非空即跳过，可重复运行。
用法：python enrich_versions.py [--limit N] [--all]
"""
import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_review_weak import PROVIDERS, load_dotenv   # noqa: E402
from enrich_llm import ask_llm                       # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "index.sqlite"

PROMPT = """从下面的漏洞情报中抽取版本信息，只输出 JSON，不要其他文字：
{{"affected": "<受影响版本区间，如 <=1.82.4 或 3.8.0~3.8.1>", "fixed": "<修复版本，如 1.84.0>", "known": true}}

规则：
1. 只依据给出的文本；文本中没有明确版本信息时输出 {{"known": false}}。
2. 禁止推测或编造版本号——不确定就是 known=false。

漏洞编号：{cve_id}
中文摘要：{summary}
原始描述（英文）：
{content}"""


def pick_provider(env):
    ds = env.get(PROVIDERS["deepseek"]["env"], "")
    if ds:
        return "deepseek", PROVIDERS["deepseek"]["model"], ds
    sf = env.get(PROVIDERS["siliconflow"]["env"], "")
    if sf:
        return "siliconflow", PROVIDERS["siliconflow"]["model"], sf
    raise SystemExit("无可用 LLM key")


def version_in_text(ver: str, text: str) -> bool:
    """防编造：抽取的版本数字串必须在原文出现（去 <=、>=、v 等修饰后核对）。"""
    if not ver:
        return False
    for token in re.findall(r"\d+(?:\.\d+)+", ver):
        if token not in text:
            return False
    return bool(re.search(r"\d", ver))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--all", action="store_true", help="跑全部 AI 相关漏洞（默认仅 CVSS>=9）")
    args = ap.parse_args()

    env = load_dotenv()
    provider, model, key = pick_provider(env)
    base = PROVIDERS[provider]["base"]
    print(f"[versions] provider={provider} model={model}")

    db = sqlite3.connect(str(DB))
    where = "ai_related=1 AND (v.affected_versions IS NULL OR v.affected_versions='')"
    if not args.all:
        where += " AND cvss>=9"
    rows = db.execute(
        f"""SELECT v.cve_id, v.cvss, v.summary_zh,
                   (SELECT content_md FROM records WHERE id='cve-'||v.cve_id)
            FROM vuln_meta v WHERE {where}
            ORDER BY v.cvss IS NULL, v.cvss DESC""").fetchall()
    if args.limit:
        rows = rows[: args.limit]
    print(f"[versions] 待处理 {len(rows)} 条")

    ok = unknown = fail = 0
    t0 = time.time()
    for i, (cve_id, cvss, summary, content) in enumerate(rows, 1):
        summary = (summary or "")[:500]
        content = (content or "")[:2500]
        data = ask_llm(base, model, key,
                       PROMPT.format(cve_id=cve_id, summary=summary, content=content), 60)
        if not data or not isinstance(data, dict):
            fail += 1
            print(f"[{i}/{len(rows)}] {cve_id} 解析失败，跳过")
            continue
        if not data.get("known"):
            unknown += 1
            continue
        aff, fix = str(data.get("affected") or "").strip(), str(data.get("fixed") or "").strip()
        # 防编造：版本号必须出现在原文
        if not version_in_text(aff, content + summary):
            unknown += 1
            print(f"[{i}/{len(rows)}] {cve_id} 版本串未在原文出现，拒收（防编造）")
            continue
        ver = f"影响 {aff}"
        if fix and version_in_text(fix, content + summary):
            ver += f"；升级 {fix} 修复"
        db.execute("UPDATE vuln_meta SET affected_versions=? WHERE cve_id=?", (ver, cve_id))
        db.commit()
        ok += 1
        print(f"[{i}/{len(rows)}] {cve_id} → {ver}")
        time.sleep(0.4)

    db.close()
    print(f"\n[versions] 完成：成功 {ok}，无版本信息 {unknown}，失败 {fail}，"
          f"耗时 {(time.time()-t0)/60:.1f} 分钟")
    return 0


if __name__ == "__main__":
    sys.exit(main())

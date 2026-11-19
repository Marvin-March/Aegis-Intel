#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo.py —— 答辩演示脚本（任务书 §三·第 6 步）

三连问演示流，展示三类问题分层路由：
  1. 点查：  "CVE-2026-59822 是什么？"      → SQL 直查 enrich_json 卡片
  2. 语义：  "针对 MCP 工具链的供应链攻击有哪些？" → 向量检索 + 缝合表卡片
  3. 关联：  "这些漏洞有哪些分析文章？"      → article_cve 反查（关联推理通道）
另含诚实拒答彩蛋："CVE-2024-3094 是什么？"（库内无此记录 → 拒答 + NVD 链接）

用法:
    uv run python scripts/demo.py [--model <路径>] [--no-qa]   # --no-qa 只看检索不走生成
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from search import search, CVE_RE, related_articles  # noqa: E402
from qa import answer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

DIFY_Q = "Dify 的 SSRF 漏洞怎么修？"   # 冒烟实测：该文章块带 cve_ids 元数据 → 缝合表增强的主场


def banner(t: str):
    print("\n" + "─" * 60)
    print(t)
    print("─" * 60)


def show_search(r: dict, top: int = 3):
    print(f"[路由] {r['route']}")
    for h in r["hits"][:top]:
        print(f"  {h['score']:.3f} [{h['meta'].get('domain')}/{h['meta'].get('source')}] "
              f"{h['meta'].get('title','')[:56]}")
    for c in r["cards"]:
        print(f"  [卡] {c['cve_id']} | {c.get('summary_zh','')[:64]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="", help="覆盖模型路径")
    ap.add_argument("--no-qa", action="store_true", help="只展示检索过程，不走生成")
    args = ap.parse_args()
    if args.model:
        import emb as _e
        _e.CANDIDATE_PATHS.insert(0, args.model)

    t0 = time.time()

    # ── 第一问：点查 ──────────────────────────────
    banner("第一问 · 点查通道：CVE-2026-59822 是什么？")
    r1 = search("CVE-2026-59822 是什么？")
    show_search(r1)
    if not args.no_qa:
        print("\n[回答]")
        print(answer("CVE-2026-59822 是什么？")["answer"])

    # ── 第二问：语义 + 缝合表增强 ──────────────────
    banner("第二问 · 语义通道 + 缝合表增强：Dify 的 SSRF 漏洞怎么修？")
    r2 = search(DIFY_Q)
    show_search(r2)
    if not args.no_qa:
        print("\n[回答]")
        print(answer(DIFY_Q)["answer"])

    # ── 第三问：关联 ──────────────────────────────
    banner("第三问 · 关联通道：这些漏洞（article_cve 反查）有哪些分析文章？")
    cve_ids = [c["cve_id"] for c in r2["cards"]]
    arts = related_articles(cve_ids)
    if arts:
        for a in arts:
            print(f"  [{a['cve_id']}] 《{a['title'][:50]}》({a['source']}) {a['url']}")
    else:
        print("  （article_cve 反查为空）")
    if not args.no_qa:
        print("\n（关联通道 = article_cve 反查，规则+JOIN 直出结构化列表，零 LLM 成本）")

    # ── 彩蛋：诚实拒答 ────────────────────────────
    banner("彩蛋 · 诚实拒答：CVE-2024-3094 是什么？（库内无此记录）")
    print(answer("CVE-2024-3094 是什么？")["answer"])

    print(f"\n[demo] 全程 {time.time()-t0:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

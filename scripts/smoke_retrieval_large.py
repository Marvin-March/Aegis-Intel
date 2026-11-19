#!/usr/bin/env python3
"""大规模检索基准（40 题 / 七大类）：在 4B/2560 维向量库上测语义命中率。

分类：A 组件漏洞语义 / B 攻击技术语义 / C 热点事件 / D 论文域 / E CVE 点查+诚实拒答 / F daily / G 中英混合
判定：top-8（同 url 去重）中出现期望域 且 命中期望关键词（无关键词则只看域）。
点查标准答案动态选取：vuln_meta 有富化 且 向量库确有该编号 → 才作为“应命中”用例。

用法:
  .venv/Scripts/python.exe scripts/smoke_retrieval_large.py \
      --model D:/models/WeMM-Embedding-4B --store data/vector_store [--cpu]
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from smoke_retrieval_wemm import load_model, vector_search, sql_point_query  # noqa: E402

# (问题, where, 期望域[|分隔], 必含关键词[标题/cve_ids/正文片段任一])
QUESTIONS = [
    # A 组件漏洞语义（组件知识在语料中以 cve 与文章两种形态存在）
    ("vLLM 推理引擎有哪些已知漏洞？", None, "cve|article", ["vllm"]),
    ("LiteLLM 代理服务的认证绕过漏洞是怎么回事？", None, "cve|article", ["litellm"]),
    ("n8n 工作流平台出过什么安全问题？", None, "cve|article", ["n8n"]),
    ("Langflow 的代码执行漏洞是怎么回事？", None, "cve|article", ["langflow"]),
    ("Ollama 本地模型服务有什么暴露风险？", None, "cve|article", ["ollama"]),
    ("Gradio 组件的文件路径操纵漏洞是什么？", None, "cve|article", ["gradio"]),
    ("Dify 沙箱逃逸漏洞分析到什么程度了？", None, "cve|article", ["dify"]),
    ("ComfyUI 有没有已知漏洞？", None, "cve|article", ["comfyui"]),
    # B 攻击技术语义
    ("针对 MCP 工具描述的投毒攻击有哪些案例？", None, "article|paper", ["mcp"]),
    ("提示词注入的防御清单有哪些要点？", None, "article|paper", []),
    ("大模型越狱攻击的最新手法有哪些？", None, "article|paper", []),
    ("AI 应用沙箱逃逸的利用链是怎样的？", None, "article|paper", []),
    ("神经网络后门攻击怎么检测？", None, "article|paper", []),
    ("RAG 知识库投毒攻击如何实现与防御？", None, "article|paper", []),
    ("AI 钓鱼邮件生成攻击有什么研究？", None, "article|paper", []),
    ("蜜罐在 AI 攻防里怎么用？", None, "article|paper", []),
    ("智能体的敏感数据外传路径有哪些？", None, "article|paper", []),
    ("勒索软件结合 AI 的攻击趋势如何？", None, "article|paper", []),
    ("模型权重窃取攻击的可行性分析", None, "article|paper", []),
    # C 热点事件 / 产品
    ("微软 M365 Copilot 的 EchoLeak 零点击漏洞原理是什么？", None, "article|cve", ["copilot"]),
    ("Claude 相关的安全漏洞或滥用事件有哪些？", None, "article|cve", ["claude"]),
    ("ChatGPT 越狱事件有哪些分析？", None, "article|paper", []),
    ("多智能体系统的权限混淆攻击怎么防？", None, "article|paper", []),
    ("AI 浏览器 Agent 的安全风险有哪些？", None, "article|cve", []),
    ("机器学习供应链攻击的典型手法有哪些？", None, "article|paper", []),
    # D 论文域（意图词路由 → domain=paper）
    ("有没有关于 AI Agent 攻击基准的论文？", {"domain": "paper"}, "paper", []),
    ("用合成数据优化 AI 智能体攻击的研究", {"domain": "paper"}, "paper", []),
    ("jailbreak 越狱模糊测试相关的学术工作", {"domain": "paper"}, "paper", []),
    ("联邦学习模型投毒的论文有哪些？", {"domain": "paper"}, "paper", []),
    ("提示注入攻防的学术研究进展", {"domain": "paper"}, "paper", []),
    # F daily
    ("2026 年 9 月下旬的每日 AI 安全资讯都报了什么？", {"domain": "daily"}, "daily", []),
    # G 中英混合 / 表述变体
    ("MCP tool poisoning attack 的原理与案例", None, "article|paper", ["mcp"]),
    ("LLM chain-of-thought 泄露会带来什么风险？", None, "article|paper", []),
    ("AI security governance best practices 有哪些参考？", None, "article|paper", []),
    ("智能体 tool calling 被滥用的攻击面分析", None, "article|paper", []),
]

HONESTY_CASES = ["CVE-2024-3094", "CVE-2099-1111"]  # 真实存在但库内无 / 编造编号


def pick_point_query_cves(vstore_path: Path, n: int = 3) -> list[str]:
    """从 vuln_meta 选有中文摘要的高分 CVE，且向量库确有该编号 → 标准答案。"""
    con = sqlite3.connect(f"file:{(ROOT / 'data' / 'index.sqlite').as_posix()}?mode=ro", uri=True)
    cand = con.execute(
        "SELECT cve_id FROM vuln_meta WHERE summary_zh != '' AND cvss >= 8 "
        "ORDER BY kev DESC, cvss DESC LIMIT 40").fetchall()
    con.close()
    db = vstore_path / "chroma.sqlite3"
    vs = sqlite3.connect(  # Windows 绝对路径带盘符会破坏 sqlite URI，转相对路径
        f"file:{os.path.relpath(db).replace(os.sep, '/')}?mode=ro", uri=True)
    picked = []
    for (cve,) in cand:
        cnt = vs.execute(
            "SELECT COUNT(*) FROM embedding_metadata WHERE string_value=?", (cve,)).fetchone()[0]
        if cnt > 0:
            picked.append(cve)
        if len(picked) >= n:
            break
    vs.close()
    return picked


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="D:/models/WeMM-Embedding-4B")
    ap.add_argument("--store", default=str(ROOT / "data" / "vector_store"))
    ap.add_argument("--out", default=str(ROOT / "runs" / "smoke_retrieval_large.json"))
    ap.add_argument("--cpu", action="store_true")
    args = ap.parse_args()

    import chromadb

    model, device = load_model(args.model, force_cpu=args.cpu)
    client = chromadb.PersistentClient(path=args.store)
    col = client.get_or_create_collection("intel")
    print(f"[store] count={col.count()}")

    results = []
    top1_scores = []
    cat_stat: dict[str, list[bool]] = {}

    def grade(cat: str, q: str, where, expect_domain: str, keywords: list) -> None:
        hits, embed_s = vector_search(model, col, q, where)
        top1_scores.append(hits[0]["score"])
        expected_set = expect_domain.split("|")
        domain_ok = any(h["meta"]["domain"] in expected_set for h in hits)
        blob = " ".join(f"{h['meta']['title']} {h['meta']['cve_ids']} {h['snippet']}"
                        for h in hits)
        kw_hit = [k for k in keywords if k.lower() in blob.lower()]
        ok = domain_ok and (not keywords or bool(kw_hit))
        cat_stat.setdefault(cat, []).append(ok)
        results.append({"cat": cat, "q": q, "where": str(where), "ok": ok,
                        "domain_ok": domain_ok, "keyword_hit": kw_hit,
                        "top1_score": hits[0]["score"], "embed_s": round(embed_s, 2),
                        "hits": [{"rank": i + 1, "score": h["score"],
                                  "domain": h["meta"]["domain"],
                                  "title": h["meta"]["title"][:70],
                                  "cve_ids": h["meta"]["cve_ids"][:60]}
                                 for i, h in enumerate(hits)]})

    t0 = time.time()
    cats = {"A": QUESTIONS[0:8], "B": QUESTIONS[8:18], "C": QUESTIONS[18:24],
            "D": QUESTIONS[24:29], "F": QUESTIONS[29:30], "G": QUESTIONS[30:34]}
    for cat, qs in cats.items():
        for q, where, dom, kws in qs:
            grade(cat, q, where, dom, kws)
            print(f"  [{cat}] {'✓' if results[-1]['ok'] else '✗'} {q}", flush=True)

    # E CVE 点查：动态标准答案 + 诚实拒答
    point_cves = pick_point_query_cves(Path(args.store), 3)
    print(f"[E] 点查标准答案: {point_cves}")
    for cve in point_cves:
        card = sql_point_query(cve)
        ok = card is not None
        cat_stat.setdefault("E点查", []).append(ok)
        results.append({"cat": "E点查", "q": f"{cve} 是什么？", "ok": ok, "card": card})
        print(f"  [E] {'✓' if ok else '✗'} 点查 {cve}")
    for cve in HONESTY_CASES:
        card = sql_point_query(cve)
        ok = card is None                      # 期待诚实返回 None
        cat_stat.setdefault("E拒答", []).append(ok)
        results.append({"cat": "E拒答", "q": f"{cve} 是什么？", "ok": ok,
                        "honest_refusal": card is None})
        print(f"  [E] {'✓' if ok else '✗'} 诚实拒答 {cve}（期待库内无 → None）")

    # 汇总
    all_ok = [o for v in cat_stat.values() for o in v]
    print(f"\n=== 总体: {sum(all_ok)}/{len(all_ok)} | 用时 {time.time()-t0:.0f}s | device={device} ===")
    for cat, v in cat_stat.items():
        print(f"  {cat}: {sum(v)}/{len(v)}")
    print(f"top1 分数: min {min(top1_scores):.3f} / 中位 {statistics.median(top1_scores):.3f} "
          f"/ max {max(top1_scores):.3f} | 低于 0.3 的 top1: {sum(1 for s in top1_scores if s < 0.3)}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"device": device, "store": args.store,
                               "total": len(all_ok), "hit": sum(all_ok),
                               "per_category": {k: f"{sum(v)}/{len(v)}" for k, v in cat_stat.items()},
                               "top1_scores": {"min": min(top1_scores),
                                               "median": statistics.median(top1_scores),
                                               "max": max(top1_scores)},
                               "point_cves": point_cves, "results": results},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"结果已写 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

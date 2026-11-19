#!/usr/bin/env python3
"""检索冒烟 10 题。查询向量库（4B/2560），报告命中域与排序。

模型加载优先级：4B int8 量化(8GB 卡可跑) → bf16 CPU 兜底（每条查询慢但可用）。
查询必须 encode_query；语料侧是 encode_document 建的库——两侧前缀不同属预期。

用法:
  .venv/Scripts/python.exe scripts/smoke_retrieval_wemm.py \
      --model D:/models/WeMM-Embedding-4B --store data/vector_store
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = "D:/models/WeMM-Embedding-4B"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# (问题, chroma where 过滤, 期望域, 期望关键词[标题/cve_ids/正文任一含即可，可空])
QUESTIONS = [
    ("有哪些针对 MCP 工具链的供应链攻击？", None, "article", ["MCP"]),
    ("Dify 的 SSRF 漏洞怎么修？", None, "article|cve", ["dify"]),   # 语料中 Dify SSRF 以文章形态为主(带 cve_ids 走缝合表)
    ("和 EchoLeak（CVE-2025-32711，M365 Copilot 提示注入泄露）类似的研究有哪些？", None, "article", ["EchoLeak", "CVE-2025-32711"]),
    ("2026 年有哪些被在野利用的 AI 漏洞？",
     {"$and": [{"domain": "cve"}, {"ai_related": 1}]}, "cve", []),
    ("提示词注入有什么防御方法？", None, "article", []),
    # 原题 CVE-2024-3094(XZ 后门)语料 0 覆盖（2024 年 CVE 仅收 426 条）；
    # 换 CVE-2026-59822（litellm，KEV+AI 相关+中文摘要，vuln_meta 与向量库双端都在）。
    # 另附诚实拒答用例：查确定不在库的编号，期待返回 None 而非编卡片
    ("CVE-2026-59822 是什么？", "SQL点查", "cve", ["CVE-2026-59822"]),
    ("有哪些关于 LLM Agent 安全的论文？", {"domain": "paper"}, "paper", []),
    ("vLLM 有哪些已知漏洞？", None, "cve", ["vllm"]),
    ("微软 Copilot 出过什么安全事件？", None, "article", ["EchoLeak", "Copilot", "CVE-2025-32711"]),
    ("越狱攻击的最新研究", None, "article|paper", []),
]


def load_model(model_path: str, force_cpu: bool = False):
    import torch
    from sentence_transformers import SentenceTransformer

    if torch.cuda.is_available() and not force_cpu:
        try:
            from transformers import BitsAndBytesConfig
            t0 = time.time()
            model = SentenceTransformer(
                model_path, trust_remote_code=True,
                model_kwargs={"quantization_config": BitsAndBytesConfig(load_in_8bit=True),
                              "device_map": {"": 0}},
                device="cuda:0")
            model.encode_query(["加载测试"], normalize_embeddings=True)
            print(f"[model] 4B int8 量化加载成功 cuda:0，耗时 {time.time()-t0:.0f}s")
            return model, "cuda:int8"
        except Exception as e:
            print(f"[model] int8 加载失败（{type(e).__name__}: {str(e)[:120]}），转 CPU bf16")
    t0 = time.time()
    model = SentenceTransformer(model_path, trust_remote_code=True,
                                model_kwargs={"dtype": "bfloat16"}, device="cpu")
    model.encode_query(["加载测试"], normalize_embeddings=True)
    print(f"[model] CPU bf16 加载成功，耗时 {time.time()-t0:.0f}s（查询会慢，属预期）")
    return model, "cpu"


def vector_search(model, col, query: str, where: dict | None, k: int = 8):
    t0 = time.time()
    q = model.encode_query([query], normalize_embeddings=True)
    embed_s = time.time() - t0
    res = col.query(query_embeddings=q.tolist(), n_results=16, where=where,
                    include=["documents", "metadatas", "distances"])
    hits, seen = [], set()
    for i in range(len(res["ids"][0])):
        url = res["metadatas"][0][i]["url"]
        if url in seen:                      # 同文多块去重，取最高分
            continue
        seen.add(url)
        hits.append({"score": round(1 - res["distances"][0][i], 4),
                     "meta": res["metadatas"][0][i],
                     "snippet": res["documents"][0][i][:150].replace("\n", " ")})
        if len(hits) >= k:
            break
    return hits, embed_s


def sql_point_query(cve_id: str) -> dict | None:
    con = sqlite3.connect(f"file:{(ROOT/'data'/'index.sqlite').as_posix()}?mode=ro", uri=True)
    row = con.execute(
        "SELECT v.cve_id, v.cvss, v.severity, v.kev, v.epss, v.summary_zh, r.url, r.title "
        "FROM vuln_meta v JOIN records r ON r.id='cve-'||v.cve_id WHERE v.cve_id=?",
        (cve_id,)).fetchone()
    con.close()
    if not row:
        return None
    return {"cve_id": row[0], "cvss": row[1], "severity": row[2], "kev": row[3],
            "epss": row[4], "summary_zh": (row[5] or "")[:120], "url": row[6], "title": row[7]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--store", default=str(ROOT / "data" / "vector_store"))
    ap.add_argument("--out", default=str(ROOT / "runs" / "smoke_retrieval.json"))
    ap.add_argument("--cpu", action="store_true",
                    help="强制 CPU bf16（int8 在本模型上有 segfault 风险时用）")
    args = ap.parse_args()

    import chromadb

    model, device = load_model(args.model, force_cpu=args.cpu)
    t0 = time.time()
    client = chromadb.PersistentClient(path=args.store)
    col = client.get_or_create_collection("intel")
    print(f"[store] count={col.count()}，打开耗时 {time.time()-t0:.0f}s")

    results = []
    hit_count = 0
    for n, (query, where, expect_domain, keywords) in enumerate(QUESTIONS, 1):
        if where == "SQL点查":
            cve_id = CVE_RE.search(query).group(0).upper()
            card = sql_point_query(cve_id)
            ok = card is not None
            results.append({"q": query, "route": "sql点查", "ok": ok, "card": card})
            hit_count += ok
            print(f"\n#{n} [SQL点查] {'✓命中' if ok else '✗未命中(库内无此编号)'} {query}")
            if card:
                print(f"   {card['cve_id']} | CVSS {card['cvss']} {card['severity']} "
                      f"| KEV {card['kev']} | {card['title'][:60]}")
            continue

        hits, embed_s = vector_search(model, col, query, where)
        top_domains = "|".join(h["meta"]["domain"] for h in hits[:3])
        blob = " ".join(f"{h['meta']['title']} {h['meta']['cve_ids']} {h['snippet']}" for h in hits)
        kw_hit = [k for k in keywords if k.lower() in blob.lower()]
        expected_set = expect_domain.split("|")
        domain_ok = any(h["meta"]["domain"] in expected_set for h in hits)
        ok = domain_ok and (not keywords or bool(kw_hit))
        hit_count += ok
        results.append({"q": query, "route": f"vector where={where}", "ok": ok,
                        "expect_domain": expect_domain, "keyword_hit": kw_hit,
                        "embed_s": round(embed_s, 1),
                        "hits": [{"rank": i + 1, "score": h["score"],
                                  "domain": h["meta"]["domain"], "source": h["meta"]["source"],
                                  "title": h["meta"]["title"][:80], "cve_ids": h["meta"]["cve_ids"],
                                  "url": h["meta"]["url"]} for i, h in enumerate(hits)]})
        print(f"\n#{n} [{'✓' if ok else '✗'}] 嵌入 {embed_s:.1f}s 期望[{expect_domain}] "
              f"关键词{kw_hit or '-'} {query}")
        for h in hits[:3]:
            print(f"   {h['score']:.3f} [{h['meta']['domain']}/{h['meta']['source']}] "
                  f"{h['meta']['title'][:66]}")

    print(f"\n=== 总命中: {hit_count}/10（通过标准 8/10）===")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"device": device, "store": args.store,
                               "hit": hit_count, "results": results},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"结果已写 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""WeMM-Embedding 检索冒烟：data/vector_store 语义查询。

用法:
  .venv/Scripts/python.exe scripts/vector_search_wemm.py "针对 MCP 工具链的供应链攻击"
  .venv/Scripts/python.exe scripts/vector_search_wemm.py "Dify SSRF 修复" --domain article -k 5
"""

from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STORE_DIR = ROOT / "data" / "vector_store"
DEFAULT_MODEL = "tencent/WeMM-Embedding-9B"


def search(query: str, k: int = 8, domain: str | None = None,
           model_id: str = DEFAULT_MODEL, dim: int = 0,
           store_dir: Path | None = None):
    import chromadb
    from sentence_transformers import SentenceTransformer

    client = chromadb.PersistentClient(path=str(store_dir or STORE_DIR))
    col = client.get_or_create_collection("intel", metadata={"hnsw:space": "cosine"})
    if col.count() == 0:
        print("向量库为空，先跑 build_vector_wemm.py")
        return []

    model = SentenceTransformer(model_id, trust_remote_code=True,
                                model_kwargs={"dtype": "bfloat16"})
    q = model.encode_query([query], truncate_dim=dim or None, normalize_embeddings=True)

    where = {"domain": domain} if domain else None
    res = col.query(query_embeddings=q.tolist(), n_results=k, where=where,
                    include=["documents", "metadatas", "distances"])
    hits = []
    for i in range(len(res["ids"][0])):
        hits.append({
            "score": 1 - res["distances"][0][i],  # cosine distance → 相似度
            "meta": res["metadatas"][0][i],
            "text": res["documents"][0][i],
        })
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("-k", type=int, default=8)
    ap.add_argument("--domain", choices=["cve", "article", "paper", "daily"], default=None)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--dim", type=int, default=0)
    ap.add_argument("--store-dir", type=Path, default=None,
                    help="默认 data/vector_store；冒烟库传 data/vector_store_smoke")
    args = ap.parse_args()

    hits = search(args.query, k=args.k, domain=args.domain,
                  model_id=args.model, dim=args.dim, store_dir=args.store_dir)
    for h in hits:
        m = h["meta"]
        print(f"\n[{h['score']:.4f}] [{m['domain']}/{m['source']}] "
              f"{m['publish_time'][:10]} cve={m['cve_ids'] or '-'}")
        print(f"  {m['title']}")
        print(f"  {m['url']}")
        print(f"  {h['text'][:180].replace(chr(10), ' ')}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

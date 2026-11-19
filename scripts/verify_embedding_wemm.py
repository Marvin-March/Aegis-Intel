#!/usr/bin/env python3
"""余弦一致性验证（任务书 §三·第 2 步，硬闸门）：四域抽 10 块，document 侧重嵌 vs 库内存量向量。

通过标准：10/10 余弦 ≥ 0.99。不过闸 = 查询侧与建库侧不一致，禁止进检索/问答层。
注意：必须用 encode_document（建库侧就是它）；encode_query 有指令前缀，比对必然对不上。

用法:
  .venv/Scripts/python.exe scripts/verify_embedding_wemm.py \
      --model D:/models/WeMM-Embedding-4B --store data/vector_store [--cpu]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent

# (名称, chroma where, 抽样数)
SAMPLES = [
    ("cve/ai_related=1", {"$and": [{"domain": "cve"}, {"ai_related": 1}]}, 2),
    ("cve/ai_related=0", {"$and": [{"domain": "cve"}, {"ai_related": 0}]}, 2),
    ("article", {"domain": "article"}, 3),
    ("paper", {"domain": "paper"}, 2),
    ("daily", {"domain": "daily"}, 1),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="D:/models/WeMM-Embedding-4B")
    ap.add_argument("--store", default=str(ROOT / "data" / "vector_store"))
    ap.add_argument("--cpu", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "runs" / "verify_embedding.json"))
    args = ap.parse_args()

    import chromadb
    from sentence_transformers import SentenceTransformer

    t0 = time.time()
    model = SentenceTransformer(args.model, trust_remote_code=True,
                                model_kwargs={"dtype": "bfloat16"},
                                device="cpu" if args.cpu else None)
    dim = (model.get_embedding_dimension()
           if hasattr(model, "get_embedding_dimension")
           else model.get_sentence_embedding_dimension())
    print(f"[model] 加载 {time.time()-t0:.0f}s, device={model.device}, dim={dim}")

    client = chromadb.PersistentClient(path=args.store)
    col = client.get_or_create_collection("intel")

    rows = []
    passed = 0
    total = 0
    for name, where, n in SAMPLES:
        got = col.get(where=where, limit=n, include=["documents", "embeddings", "metadatas"])
        ids = got["ids"]
        docs = got["documents"]
        stored = np.asarray(got["embeddings"], dtype=np.float32)
        stored = stored / np.linalg.norm(stored, axis=1, keepdims=True)
        t1 = time.time()
        re_emb = model.encode_document(docs, normalize_embeddings=True,
                                       show_progress_bar=False).astype(np.float32)
        cos = (stored * re_emb).sum(axis=1)      # 双侧已归一化，内积即余弦
        for i, c in enumerate(cos):
            total += 1
            ok = c >= 0.99
            passed += ok
            rows.append({"sample": f"{name}[{i}]", "id": ids[i], "cosine": round(float(c), 5),
                         "ok": bool(ok), "title": got["metadatas"][i]["title"][:60]})
            print(f"  {'✓' if ok else '✗'} {name}[{i}] cosine={c:.5f} "
                  f"{got['metadatas'][i]['title'][:46]}")
        print(f"[{name}] 重嵌 {len(cos)} 条耗时 {time.time()-t1:.0f}s")

    print(f"\n=== 闸门判定: {passed}/{total} ≥ 0.99 —— {'通过，查询侧与建库侧一致' if passed == total else '不通过，禁止进入检索/问答层'} ===")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"gate": f"{passed}/{total}",
                               "passed": bool(passed == total),
                               "dim": dim, "rows": rows}, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    print(f"结果已写 {out}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""WeMM-Embedding 向量建库：data/chunks.jsonl → data/vector_store (Chroma)。

前置：chunks.jsonl 由 scripts/preprocess_export.py 产出（剥头/清噪/切块已就绪，
交付时已生成，export 数据未重新导出过就不用重跑）。设计规范见 docs/向量化设计-怎么搭.md，
运行手册见 docs/向量化运行手册-WeMM.md。

- 嵌入模型默认 tencent/WeMM-Embedding-9B（bf16 需 ≥24GB 显存；8GB 卡用 --model ...2B）
- 查询/文档指令不对称：语料走 encode_document（本脚本），检索时必须走 encode_query
- id = sha1(相对路径#块序号)（preprocess 已生成），重跑自动跳过已嵌入块（断点续传）
- OOM 自动减半 batch；显存预检，权重放不下时提示换小模型

用法:
  .venv/Scripts/python.exe scripts/build_vector_wemm.py                    # 全量（默认 9B）
  .venv/Scripts/python.exe scripts/build_vector_wemm.py --sample 300 --store-dir data/vector_store_smoke   # 冒烟
  .venv/Scripts/python.exe scripts/build_vector_wemm.py --rebuild          # 删库重建
  .venv/Scripts/python.exe scripts/build_vector_wemm.py --dim 1024         # MRL 降维（默认全维 4096）
  .venv/Scripts/python.exe scripts/build_vector_wemm.py --model tencent/WeMM-Embedding-2B   # 8GB 卡
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHUNKS_JSONL = ROOT / "data" / "chunks.jsonl"
STORE_DIR = ROOT / "data" / "vector_store"
DEFAULT_MODEL = "tencent/WeMM-Embedding-9B"
MODEL_VRAM_GB = {"9B": 22, "4B": 10, "2B": 6}

# 写入 Chroma 的元数据字段（chunks.jsonl 里的其余字段忽略）
META_FIELDS = ("domain", "source", "url", "title", "publish_time",
               "chunk_index", "n_chunks", "cve_ids", "ai_related")


def load_blocks(chunks_path: Path) -> list[dict]:
    blocks: list[dict] = []
    with chunks_path.open(encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            blocks.append({
                "id": r["id"],
                "text": r["text"],
                "meta": {k: r[k] for k in META_FIELDS if k in r},
            })
    return blocks


def sample_blocks(blocks: list[dict], n: int) -> list[dict]:
    """全库均匀抽样 n 块（跨域冒烟用），n<=0 或 >= 总数时全量。"""
    if n <= 0 or n >= len(blocks):
        return blocks
    step = len(blocks) / n
    return [blocks[int(i * step)] for i in range(n)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--chunks", type=Path, default=CHUNKS_JSONL)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--dim", type=int, default=0, help="MRL 降维，0=全维（9B=4096）")
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--dtype", default="bfloat16", choices=["bfloat16", "float16", "float32"])
    ap.add_argument("--device", default=None, help="默认自动（有 CUDA 用 CUDA）")
    ap.add_argument("--flush", type=int, default=256, help="每累积多少块检查/写入一次")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 块")
    ap.add_argument("--sample", type=int, default=0, help="全库均匀抽 N 块（冒烟）")
    ap.add_argument("--rebuild", action="store_true", help="删除 vector_store 重建")
    ap.add_argument("--store-dir", type=Path, default=STORE_DIR)
    args = ap.parse_args()

    import chromadb
    import torch
    from sentence_transformers import SentenceTransformer

    if args.rebuild and args.store_dir.exists():
        import shutil
        shutil.rmtree(args.store_dir)
        print(f"[init] 已删除 {args.store_dir}")

    t0 = time.time()
    blocks = load_blocks(args.chunks)
    if args.limit:
        blocks = blocks[: args.limit]
    blocks = sample_blocks(blocks, args.sample)
    total_chars = sum(len(b["text"]) for b in blocks)
    print(f"[init] 待嵌入 {len(blocks)} 块, {total_chars/1e6:.1f}M 字符")

    size = next((k for k in MODEL_VRAM_GB if k in args.model), None)
    if torch.cuda.is_available() and size:
        free_gb = (torch.cuda.get_device_properties(0).total_memory
                   - torch.cuda.memory_reserved(0)) / 2**30
        need = MODEL_VRAM_GB[size]
        if free_gb < need:
            print(f"[warn] 显存 {free_gb:.0f}GB < {size} bf16 建议 {need}GB，大概率 OOM；"
                  f"换小模型（--model tencent/WeMM-Embedding-{'4B' if need > 10 else '2B'}）")

    model = SentenceTransformer(
        args.model, trust_remote_code=True,
        model_kwargs={"dtype": args.dtype}, device=args.device)
    dim = args.dim or (model.get_embedding_dimension()
                       if hasattr(model, "get_embedding_dimension")
                       else model.get_sentence_embedding_dimension())
    print(f"[init] 模型加载完成 device={model.device}, dtype={args.dtype}, dim={dim}")

    client = chromadb.PersistentClient(path=str(args.store_dir))
    col = client.get_or_create_collection("intel", metadata={"hnsw:space": "cosine"})

    done = 0
    skipped = 0
    buf: list[dict] = []

    def flush() -> None:
        nonlocal done, skipped
        if not buf:
            return
        ids = [b["id"] for b in buf]
        existing = set(col.get(ids=ids)["ids"])
        news = [b for b in buf if b["id"] not in existing]
        skipped += len(buf) - len(news)
        if news:
            bs = args.batch_size
            while True:
                try:
                    emb = model.encode_document(
                        [b["text"] for b in news], batch_size=bs,
                        truncate_dim=dim if args.dim else None,
                        normalize_embeddings=True, show_progress_bar=False,
                    )
                    break
                except torch.cuda.OutOfMemoryError:
                    torch.cuda.empty_cache()
                    if bs == 1:
                        raise
                    bs = max(1, bs // 2)
                    print(f"[warn] CUDA OOM，batch 降到 {bs} 重试", flush=True)
            col.upsert(
                ids=[b["id"] for b in news],
                documents=[b["text"] for b in news],
                metadatas=[b["meta"] for b in news],
                embeddings=emb.tolist(),
            )
            done += len(news)
        buf.clear()

    t1 = time.time()
    for b in blocks:
        buf.append(b)
        if len(buf) >= args.flush:
            flush()
            rate = done / max(time.time() - t1, 1)
            eta = (len(blocks) - done - skipped) / rate / 60 if rate > 0 else 0
            print(f"[run] 嵌入 {done} | 跳过 {skipped} | {rate:.0f} 块/s | ETA {eta:.0f}min", flush=True)
    flush()

    print(f"[done] 新增 {done} 块, 跳过 {skipped} 块, 库内总量 {col.count()}, "
          f"耗时 {(time.time()-t0)/60:.1f}min → {args.store_dir}")
    # 退出挂死规避（2026-10-16 实测两次）：全部工作完成后，解释器 shutdown 阶段
    # torch/chroma 线程 join 死锁 → 进程永不退出 → collect_full 的 subprocess.run
    # 无限等待，整条夜间链路卡死。数据此刻已全部落盘，os._exit 强退安全。
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())

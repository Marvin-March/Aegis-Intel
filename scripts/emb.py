#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emb.py —— 查询侧嵌入模块（WeMM-Embedding-4B，2560 维）

- 加载逻辑与建库侧 build_vector_wemm.py 同源（int8 量化 GPU → CPU bf16 兜底，
  取自 smoke_retrieval_wemm.load_model）；余弦闸门已认证一致性（10/10 ≥0.99）。
- 查询必须 encode_query；encode_document 仅用于验证比对（带指令前缀差异，混用掉召回）。
- 模型路径解析顺序：环境变量 WEM_MODEL_PATH → 命令行 --model →
  项目外层 models/WeMM-Embedding-4B → 项目根 models/WeMM-Embedding-4B。

用法:
    uv run python scripts/emb.py --check          # 加载冒烟：打印 device/dim/单条时延
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CANDIDATE_PATHS = [
    os.environ.get("WEM_MODEL_PATH", ""),
    str(ROOT.parent / "models" / "WeMM-Embedding-4B"),   # 本机下载默认位（项目外层）
    "models/WeMM-Embedding-4B",                          # 项目根下
    "tencent/WeMM-Embedding-4B",                          # HF 缓存兜底
]

_model = None
_model_path = None
_encode_lock = __import__("threading").Lock()   # 并发请求串行化编码调用（模型推理共享实例）
_load_lock = __import__("threading").Lock()     # 加载互斥：torch 并发加载会直接段错误（2026-10-15 实测 exit 139）


def resolve_model_path(explicit: str = "") -> str:
    if explicit:
        return explicit
    for p in CANDIDATE_PATHS:
        if p and (p.startswith("tencent/") or Path(p).exists()):
            return p
    return CANDIDATE_PATHS[1]


def load_model(model_path: str, force_cpu: bool = False):
    """int8 量化 GPU → CPU bf16 兜底（与 smoke_retrieval_wemm 同一份逻辑）。"""
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
            print(f"[emb] int8 cuda:0 加载成功，{time.time()-t0:.0f}s")
            return model
        except Exception as e:
            print(f"[emb] int8 失败（{type(e).__name__}: {str(e)[:100]}），转 CPU bf16")
    t0 = time.time()
    model = SentenceTransformer(model_path, trust_remote_code=True,
                                model_kwargs={"dtype": "bfloat16"}, device="cpu")
    model.encode_query(["加载测试"], normalize_embeddings=True)
    print(f"[emb] CPU bf16 加载成功，{time.time()-t0:.0f}s（查询 1-3s/条属预期）")
    return model


def get_model(force_cpu: bool = False):
    """单例加载（双检锁：并发首查只跑一次 load_model）。"""
    global _model
    if _model is None:
        with _load_lock:
            if _model is None:
                _model = load_model(resolve_model_path(), force_cpu=force_cpu)
                dim = (_model.get_embedding_dimension()
                       if hasattr(_model, "get_embedding_dimension")
                       else _model.get_sentence_embedding_dimension())
                assert dim == 2560, f"模型输出维度 {dim} ≠ 2560，与 vector_store 不匹配！"
    return _model


def embed_query(texts, force_cpu: bool = False):
    """查询侧编码（encode_query，L2 归一化）。返回 np.ndarray (n, 2560) float32。"""
    m = get_model(force_cpu=force_cpu)
    with _encode_lock:
        return m.encode_query(list(texts), normalize_embeddings=True).astype("float32")


def embed_docs(texts, force_cpu: bool = False):
    """语料侧编码（encode_document）——仅供余弦验证比对用，禁止用于检索。"""
    m = get_model(force_cpu=force_cpu)
    with _encode_lock:
        return m.encode_document(list(texts), normalize_embeddings=True).astype("float32")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="", help="覆盖模型路径（默认按 resolve 顺序找）")
    ap.add_argument("--check", action="store_true", help="加载冒烟：device/dim/单条时延")
    args = ap.parse_args()

    if args.model:
        os.environ["WEM_MODEL_PATH"] = args.model
    m = get_model()
    dim = (m.get_embedding_dimension()
           if hasattr(m, "get_embedding_dimension")
           else m.get_sentence_embedding_dimension())
    print(f"[emb] device={m.device} dim={dim}")
    if args.check:
        t0 = time.time()
        v = embed_query(["测试查询"])
        print(f"[emb] 单条查询编码 {time.time()-t0:.1f}s 形状={v.shape} 归一化={float(v[0].dot(v[0])):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

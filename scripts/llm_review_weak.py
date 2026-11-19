#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_review_weak.py —— B2 最小版：用 LLM 复核 vuln_meta 里的 weak AI 信号

背景：规则匹配的 ai_signal='weak'（仅描述词命中）误报率 30-40%（审计实测），
     把近千条非 AI CVE 带进"AI 库"会在答辩时穿帮。本脚本逐条让 LLM 复核，
     裁决写回 vuln_meta.llm_ai_related，同时更新 ai_related 作为权威过滤列。

双兼容：GLM（智谱，glm-4-flash 免费，推荐）/ DeepSeek，均为 OpenAI 兼容接口。
凭据：--api-key 参数 > 环境变量 GLM_API_KEY / DEEPSEEK_API_KEY > 项目根 .env 文件。

用法：
    uv run python scripts/llm_review_weak.py --dry-run            # 先看要复核多少条
    uv run python scripts/llm_review_weak.py --provider glm       # GLM（.env 填 GLM_API_KEY）
    uv run python scripts/llm_review_weak.py --provider deepseek  # DeepSeek
    uv run python scripts/llm_review_weak.py --limit 20           # 试跑 20 条看准确率
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

PROVIDERS = {
    "glm": {"base": "https://open.bigmodel.cn/api/paas/v4",
            "model": "glm-4.5-flash", "env": "GLM_API_KEY"},
    "deepseek": {"base": "https://api.deepseek.com",
                 "model": "deepseek-chat", "env": "DEEPSEEK_API_KEY"},
}

PROMPT = """你是安全情报分类员。判断下面这条 CVE 是否属于"AI 安全漏洞库"。

判定为相关（1）——满足任一即可：
A. 受影响组件本身属于 AI/ML 软件栈：
   - 训练/推理框架：tensorflow、pytorch/torch、keras、jax、onnx、paddlepaddle
   - LLM 应用层：langchain、llama-index、dify、open-webui、gradio、streamlit、comfyui、autogen、crewai、litellm
   - 推理服务：vllm、ollama、tgi、text-generation-webui、gpt4all、llama-cpp-python
   - ML 平台与配套：mlflow、wandb、huggingface/transformers/datasets/tokenizers/diffusers/accelerate
   ★ 只要组件在 AI 软件栈内，无论漏洞类型是常规内存安全/文件读写/反序列化/权限问题，一律判 1
B. 漏洞机理依赖 AI 特性：提示词注入、越狱、训练数据投毒、对抗样本、agent 工具滥用失控等

判为不相关（0）：
- 组件与 AI 无关，仅标题/描述出现"neural/智能/推荐系统"等泛化词（如 Linux kernel 的神经网络驱动、
  名叫 Duo 的功能、叫 AI 的产品名）；或与 AI 毫无关联的普通软件漏洞

CVE：{cve_id}
标题：{title}
描述：{desc}

只回 JSON：{{"ai_related": 0或1, "reason": "10字内理由"}}"""


# 确定性兜底：标题/描述命中 AI 包名（词边界）→ 直接判 1，不过 LLM。
# 背景：glm-4-flash 实测会把 "Insecure Temporary File in mlflow" 判成非AI——组件名识别这活不需要智力
AI_PKGS = ("tensorflow", "pytorch", "torch", "torchvision", "keras", "jax", "paddlepaddle",
           "onnx", "langchain", "llama-index", "llamaindex", "llama-cpp", "dify",
           "open-webui", "openwebui", "gradio", "streamlit", "comfyui", "autogen", "crewai",
           "litellm", "vllm", "ollama", "text-generation-webui", "gpt4all", "mlflow", "wandb",
           "huggingface", "transformer", "transformers", "datasets", "tokenizers", "diffusers",
           "accelerate", "openai", "anthropic", "google-generativeai", "whisper", "invokeai",
           "jupyter-ai", "docling", "guardrails", "chromadb", "milvus", "qdrant", "weaviate",
           "langfuse", "mcp server", "model context protocol",
           # 2026-10-03 扩充：新生态家族（MCP 服务器补扫实测漏报 112 条后的教训）
           "sglang", "xinference", "bentoml", "faiss", "pgvector", "pinecone", "lancedb",
           "langgraph", "langflow", "flowise", "librechat", "lobechat", "anythingllm",
           "ragflow", "fastgpt", "maxkb", "dspy", "semantic-kernel", "promptfoo", "garak",
           "pyrit", "axolotl", "deepspeed", "llama-factory", "stable-diffusion",
           "automatic1111", "fooocus", "controlnet", "chatglm", "qwen", "baichuan",
           "internlm", "deepseek", "lm-studio", "lmstudio", "peft", "unsloth",
           "gpt", "chatgpt", "claude", "gemini", "llama", "copilot",
           # 2026-10-07 回收池实测补充：letta(MemGPT) 被 glm-4-flash 判"普通RCE"——
           # AI Agent 框架这层识别不需要智力，白名单兜底（mlflow 教训重演）
           "letta", "memgpt", "amazon q", "bedrock agent", "autogen-studio")
AI_PKG_RE = re.compile(r"(?<![a-z0-9_-])(" + "|".join(sorted(AI_PKGS, key=len, reverse=True)) +
                       r")(?![a-z0-9])", re.I)   # 尾界允许连字符：'GPT-4'/'llama-cpp' 也能命中前缀词


def load_dotenv() -> dict:
    env = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def ask_llm(base, model, key, cve_id, title, desc, timeout):
    """调 chat/completions，从回复里抠出 JSON 裁决。失败返回 (None, '')（不猜）。
    429 限流时自动降级 glm-4-flash（两档模型限流池独立，2026-10-14 实测）。"""
    models = [model] if model == "glm-4-flash" else [model, "glm-4-flash"]
    for m in models:
        body = {"model": m, "temperature": 0,
                "messages": [{"role": "user",
                              "content": PROMPT.format(cve_id=cve_id, title=title,
                                                       desc=(desc or "")[:1200])}]}
        for attempt in range(3):
            try:
                r = requests.post(f"{base}/chat/completions",
                                  headers={"Authorization": f"Bearer {key}"},
                                  json=body, timeout=timeout)
                if r.status_code == 429 and m != "glm-4-flash":
                    print(f"  [{cve_id}] {m} 429 限流，降级 glm-4-flash")
                    break                  # 不空等重试，直接换稳定档
                if r.status_code == 429:
                    time.sleep(5 * (attempt + 1))
                    continue
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"]
                m2 = re.search(r"\{[^{}]*\}", text, re.S)
                if m2:
                    verdict = json.loads(m2.group())
                    v = verdict.get("ai_related")
                    if v in (0, 1, "0", "1"):
                        return int(v), str(verdict.get("reason", ""))[:60]
                    return None, ""
            except (requests.RequestException, KeyError, ValueError) as e:
                print(f"  [{cve_id}] {type(e).__name__}，重试 {attempt + 1}/3")
                # 免费档实测（2026-10-07）：服务在"分钟级好/坏窗口"间振荡——坏窗口内所有请求
                # 集体挂起。超时类失败等一个窗口（45s）再试，而不是 3 连发全烧在同一坏窗口里。
                wait = 45 if isinstance(e, requests.Timeout) else 3 * (attempt + 1)
                time.sleep(wait)
    return None, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="glm", choices=list(PROVIDERS))
    ap.add_argument("--api-key", default="")
    ap.add_argument("--model", default="", help="覆盖默认模型（如 glm-4-air）")
    ap.add_argument("--db", default=str(ROOT / "data" / "index.sqlite"))
    ap.add_argument("--limit", type=int, default=0, help="只复核前 N 条（0=全部 weak）")
    ap.add_argument("--sleep", type=float, default=0.4)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    db = sqlite3.connect(args.db)
    cols = {r[1] for r in db.execute("PRAGMA table_info(vuln_meta)").fetchall()}
    if "llm_ai_related" not in cols:
        db.execute("ALTER TABLE vuln_meta ADD COLUMN llm_ai_related INTEGER")
    if "llm_reason" not in cols:
        db.execute("ALTER TABLE vuln_meta ADD COLUMN llm_reason TEXT DEFAULT ''")
    db.commit()
    rows = db.execute("""SELECT v.cve_id, r.title,
            COALESCE(NULLIF(r.summary,''), substr(r.content_md,1,1200), r.title)
        FROM vuln_meta v JOIN records r
          ON r.id IN ('cve-'||v.cve_id, 'advisory-'||v.cve_id, 'ghsa-'||v.cve_id)
        WHERE v.ai_signal='weak' AND v.llm_ai_related IS NULL
        ORDER BY v.cve_id""").fetchall()
    if args.limit:
        rows = rows[:args.limit]
    print(f"待复核 weak 信号：{len(rows)} 条（provider={args.provider}）")
    if args.dry_run:
        for cve_id, title, _ in rows[:5]:
            print(f"  例：{cve_id}  {title[:60]}")
        return

    cfg = PROVIDERS[args.provider]
    key = args.api_key or __import__("os").environ.get(cfg["env"], "") or load_dotenv().get(cfg["env"], "")
    if not key:
        sys.exit(f"未找到 {cfg['env']}：--api-key 传入、环境变量或写入项目根 .env")
    model = args.model or cfg["model"]

    stats = {1: 0, 0: 0, None: 0}
    for i, (cve_id, title, desc) in enumerate(rows, 1):
        text = f"{title} {desc}"
        m = AI_PKG_RE.search(text)
        if m:   # 包名命中：确定性判 1，不烧 API
            v, reason = 1, f"包名命中:{m.group(1)}"
        else:
            v, reason = ask_llm(cfg["base"], model, key, cve_id, title, desc, args.timeout)
        if v is not None:
            db.execute("UPDATE vuln_meta SET llm_ai_related=?, llm_reason=?, ai_related=? WHERE cve_id=?",
                       (v, reason, v, cve_id))
        stats[v] += 1
        if i % 50 == 0:
            db.commit()
            print(f"  进度 {i}/{len(rows)}  AI相关={stats[1]} 非AI={stats[0]} 未裁决={stats[None]}")
        time.sleep(args.sleep)
    db.commit()
    left = db.execute("SELECT COUNT(*) FROM vuln_meta WHERE ai_signal='weak' AND llm_ai_related IS NULL").fetchone()[0]
    print(f"完成：AI相关 {stats[1]} / 非 AI {stats[0]} / 未裁决 {stats[None]}；剩余未复核 {left} 条")
    print("AI 库新口径：ai_related=1 =", db.execute("SELECT COUNT(*) FROM vuln_meta WHERE ai_related=1").fetchone()[0])


if __name__ == "__main__":
    main()

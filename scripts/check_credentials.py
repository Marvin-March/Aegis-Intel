#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_credentials.py —— 凭据健康检查（答辩前 10 秒确认全部凭据状态）

对应《爬虫收官计划》凭据管理方案第④环：一键检测所有可选凭据是否有效/缺失，
缺失不影响核心功能（显示 optional），失效给出更新指引。

用法：uv run python scripts/check_credentials.py
"""

import os
import re
import sys
from pathlib import Path

import requests

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


def load_env() -> dict:
    """读 .env（不存在则返回空，全部按未配置处理）。"""
    creds = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
            if m and m.group(2).strip():
                creds[m.group(1)] = m.group(2).strip()
    return creds


def check_deepseek(key: str) -> str:
    if not key:
        return "optional · 未配置（问答生成不可用，检索不受影响）"
    try:
        r = requests.post("https://api.deepseek.com/chat/completions",
                          headers={"Authorization": f"Bearer {key}"},
                          json={"model": "deepseek-chat",
                                "messages": [{"role": "user", "content": "ping"}],
                                "max_tokens": 1},
                          timeout=15)
        if r.status_code == 200:
            return "✓ 有效"
        if r.status_code == 401:
            return "✗ 无效或余额不足（platform.deepseek.com 检查）"
        return f"? HTTP {r.status_code}"
    except requests.RequestException as e:
        return f"? 网络异常 {type(e).__name__}"


def check_nvd(key: str) -> str:
    if not key:
        return "optional · 未配置（限流模式运行）"
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                         headers={"apiKey": key}, timeout=15)
        return "✓ 有效" if r.status_code == 200 else f"✗ HTTP {r.status_code}"
    except requests.RequestException as e:
        return f"? 网络异常 {type(e).__name__}"


def check_github(token: str) -> str:
    if not token:
        return "optional · 未配置（60次/时）"
    try:
        r = requests.get("https://api.github.com/rate_limit",
                         headers={"Authorization": f"Bearer {token}"}, timeout=15)
        if r.status_code == 200:
            core = r.json()["resources"]["core"]
            return f"✓ 有效（剩余 {core['remaining']}/{core['limit']}）"
        return f"✗ HTTP {r.status_code}"
    except requests.RequestException as e:
        return f"? 网络异常 {type(e).__name__}"


def check_butian(cookie: str) -> str:
    if not cookie:
        return "optional · 未配置（仅公开元数据通道）"
    try:
        r = requests.get("https://forum.butian.net/ai_security/349",
                         headers={"Cookie": cookie,
                                  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"},
                         timeout=20)
        if r.status_code == 200 and "article-login-overlay" not in r.text:
            return "✓ 有效（可抓全文）"
        return "✗ 已失效 → 重新登录 forum.butian.net，更新 .env 的 BUTIAN_COOKIE"
    except requests.RequestException as e:
        return f"? 网络异常 {type(e).__name__}"


def main():
    creds = load_env()
    if not ENV_FILE.exists():
        print(f"[info] .env 不存在（{ENV_FILE}）——零凭据模式，系统可正常运行公开通道")
    checks = [
        ("DEEPSEEK_API_KEY", "问答生成", check_deepseek(creds.get("DEEPSEEK_API_KEY", ""))),
        ("NVD_API_KEY", "NVD 提速", check_nvd(creds.get("NVD_API_KEY", ""))),
        ("GITHUB_TOKEN", "GitHub 提速", check_github(creds.get("GITHUB_TOKEN", ""))),
        ("BUTIAN_COOKIE", "补天全文", check_butian(creds.get("BUTIAN_COOKIE", ""))),
        ("CNNVD_ACCOUNT", "CNNVD 历史", "optional · 人工一次性下载通道，无需在线检测"),
    ]
    print("== 凭据健康检查 ==")
    for name, purpose, result in checks:
        print(f"  {name:18s} [{purpose}]  {result}")
    print("\n结论: 核心能力（采集/检索/浏览）不依赖任何凭据；标 ✗ 的项按提示更新 .env 即可恢复")


if __name__ == "__main__":
    main()

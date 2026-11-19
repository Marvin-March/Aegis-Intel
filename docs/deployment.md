# 部署与运行

## 环境

| 项 | 要求 |
|---|---|
| 操作系统 | Windows 10/11 或 Linux |
| Python | 3.12+ |
| 包管理 | uv |
| Node.js | 18+（仅前端） |
| 浏览器 | Playwright Chromium（采集需要） |
| 网络 | 可访问 NVD、arXiv、RSS 源；代理可选 |

## 安装

```bash
uv sync
uv run playwright install chromium

cp .env.example .env
cp config.example.json config.json
```

`.env` 中至少配置生成模型 Key（如 `DEEPSEEK_API_KEY`）；NVD、GitHub Token、社区 Cookie 均为可选。

`config.json` 是本地运行时配置，不入版本库；如需修改采集源、关键词或代理，改这一份即可，不要提交。

## 模型

下载 `WeMM-Embedding-4B` 到以下任一位置：

1. `models/WeMM-Embedding-4B`（项目外层或项目根）；
2. 设置 `WEM_MODEL_PATH` 指向模型目录。

构建向量库与查询必须使用同一模型，保证维度与语义空间一致。

## 数据

仓库不包含 `data/`。两种方式获得数据：

```bash
# A. 从零采集（首次较慢）
uv run python scripts/run_daily.py --mode backfill
uv run python scripts/enrich_daily.py

# B. 使用单独发布的数据包，解压到项目根 data/
```

## 启动

```bash
# API（:8000）
uv run uvicorn scripts.api:app --host 0.0.0.0 --port 8000

# 前端开发
cd frontend && npm ci && npm run dev

# 前端生产构建（由 api.py 托管 frontend/dist）
cd frontend && npm ci && npm run build
```

## 定时任务

```bash
uv run python scripts/setup_schedule.py          # 注册每日采集/富化任务
uv run python scripts/setup_schedule.py --status
uv run python scripts/setup_schedule.py --remove
```

## 常见问题

- **Playwright 下载慢**：设置 `PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright`；
- **模型找不到**：设置 `WEM_MODEL_PATH`，或在 `models/WeMM-Embedding-4B` 放置模型；
- **采集源超时**：在 `config.json` 配置代理，或等待下一次增量；
- **问答无生成**：检查 `.env` 中的 LLM Key 与配额；检索链路不需要 Key。

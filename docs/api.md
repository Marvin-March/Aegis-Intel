# API 说明

服务入口：`uv run uvicorn scripts.api:app --host 0.0.0.0 --port 8000`

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/health` | 健康检查、模型与向量库状态 |
| GET | `/api/stats` | 看板统计：记录数、向量块、AI 漏洞、类别分布 |
| POST | `/search` | 仅检索，不生成回答 |
| POST | `/ask` | 检索 + LLM 生成 + 防幻觉校验 |
| GET | `/related` | 按 CVE 反查关联文章/论文 |
| GET | `/api/vulns` | 漏洞列表与筛选 |
| GET | `/api/runs` | 采集/富化运行记录 |
| POST | `/api/collect` | 触发一次采集（前端“立即采集”） |

## `/ask` 请求示例

```json
{
  "query": "CVE-2026-59822 是什么漏洞？",
  "k": 8,
  "history": []
}
```

响应包含 `answer`、`cards`、`hits`、`fabrications` 等字段；前端用 `[卡N]`/`[N]` 锚点关联证据。

## 鉴权

本项目默认面向本地/内网部署，未内置鉴权。公网部署请在反向代理层增加认证、限流与 HTTPS。

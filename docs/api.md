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

## 资产研判接口

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/api/triage/summary` | 资产、受影响项与工单总览（看板顶部数字） |
| GET | `/api/triage/findings` | 受影响结论列表；支持 `priority` / `asset_id` / `limit` |
| GET | `/api/triage/tickets` | 工单列表；支持按 `status` 筛选 |
| GET | `/api/triage/ticket/{ticket_id}` | 单张工单：Markdown 正文、结构化证据、审批留痕 |
| POST | `/api/triage/ticket/{ticket_id}/decision` | 审批决定；证据失效、审批人不符、缺意见都会被拒绝 |

资产台账与工单表与情报库同库（`data/index.sqlite`），首次调用时自动建表。
接入方式与状态机见 [asset-triage.md](asset-triage.md)。

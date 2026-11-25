# Aegis Intel 前端工作台

智能体驱动的 AI 安全知识情报系统 · 前端工作台（Obsidian Precision 深色 SOC 风格）。

## 技术栈

- React 18 + Vite 5 + TypeScript
- Tailwind CSS 3（CSS 变量主题，深色 SOC 风格）
- lucide-react（图标）
- 无 UI 组件库依赖

## 新界面能力

- **侧栏工作台**：智能问答 / 数据看板 / 情报监测三 Tab，会话列表常驻左侧
- **⌘K 命令面板**：切 Tab、开会话、发快捷问题，Raycast / Linear 风格
- **证据对照抽屉**：点击答案里的 `[n]` / `[卡n]`，右侧滑出原文切片或 CVE 卡片，不打断阅读
- **答案导出**：一键把单轮问答（答案 + 卡片 + 命中）导出为 Markdown 简报
- **深色主题**：`src/index.css` 定义 `--bg-* / --accent-* / --status-*` 语义色，`tailwind.config.js` 映射为 `soc-*` 色阶
- **每日简报导出**：`utils/exportBrief.ts` 生成可存档的研判简报

## 开发

```bash
npm ci                # 按 package-lock 安装
npm run dev           # 5173，Vite 代理 /ask /search /health /related /api → 127.0.0.1:8000
npm run build         # tsc + vite build，产物在 dist/
npm run preview       # 预览 dist/
```

生产构建完成后，`scripts/api.py` 会直接托管 `frontend/dist`：

```bash
uv run uvicorn scripts.api:app --host 0.0.0.0 --port 8000
# 浏览器打开 http://127.0.0.1:8000
```

无需重启后端，刷新浏览器（建议 Ctrl+F5 清缓存）即可看到新界面。

## API 契约

后端接口为 `scripts/api.py`（FastAPI），契约定义在 `src/types/contract.ts`：

- **POST /ask** — 问答主接口（检索 + DeepSeek 生成 + 编号校验）
  - 请求：`{query, domain, ai_only, k, with_answer, history}`
  - 响应：`{route, hits, cards, answer, refused, fabrications, elapsed_s}`
  - 引用约定：答案里 `[n]` = hits 第 n 条；`[卡n]` = cards 第 n 张（均渲染为可点击定位）
- **POST /search** — 只检索不生成（响应 = /ask 去掉 answer/refused/fabrications）
- **GET /health** — `{status, model, store_count, uptime_s}`，前端启动探活
- **GET /related?cve_ids=a,b** — 关联文章反查（`article_cve` 缝合表，零 LLM 成本）
- **GET /api/stats** — 看板统计
- **GET /api/vulns?severity=&attack=&limit=** — 看板下钻漏洞清单
- **GET /api/runs** — 采集/富化运行历史
- **POST /api/collect** — 手动触发全链路采集（带防撞锁）

## 对接形态

- **模式 A（生产，同端口）**：`npm run build` → `uv run uvicorn scripts.api:app --port 8000` → 打开 `http://localhost:8000`
- **模式 B（开发联调）**：`npm run dev`（5173），Vite 代理 `/ask /search /health /related /api` 到 `127.0.0.1:8000`
- **模式 C（远程）**：设 `VITE_API_BASE=http://<后端IP>:8000` 后 `npm run build` / `npm run dev`

## Mock 开关

唯一开关位置：`src/api/client.ts`

```ts
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';
```

- 默认**关闭**（不打 mock 补丁时走真实后端）
- `.env` / `.env.production` 均为 `VITE_USE_MOCK=false`
- 需要纯前端演示时显式设 `VITE_USE_MOCK=true`
- 演示模式内部强制 mock（`forceMock` 参数），不影响真实模式

## 超时设置

| 请求 | 超时 |
|---|---|
| `/ask`、`/search` | 240s（生成段可能 9–31s，深度回答最长 ~120s） |
| `/api/stats`、`/api/vulns`、`/api/runs` | 30s |
| `/related` | 15s |
| `/health` | 5s |

## 目录结构

```text
frontend/
├─ src/
│  ├─ api/client.ts        # API 客户端 + mock 开关 + 超时
│  ├─ components/          # 页面与组件
│  │  ├─ ui/               # Button / Panel / Badge / BrandIcons / tokens
│  │  ├─ CommandPalette.tsx
│  │  ├─ EvidenceDrawer.tsx
│  │  ├─ Starfield.tsx
│  │  └─ ...
│  ├─ hooks/useDemoPlayer.ts
│  ├─ mocks/               # mock 数据（仅 USE_MOCK=true 时使用）
│  ├─ types/contract.ts    # 与 api.py 的响应契约
│  └─ utils/               # storage / animation / exportBrief
├─ index.html
├─ vite.config.ts
├─ tailwind.config.js
└─ package.json
```

## 注意事项

- 生产构建产物 `dist/` 由 FastAPI `StaticFiles` 托管，前端路由是 Tab 状态，不需要后端 history fallback
- `VITE_USE_MOCK` 默认 false；不要在未显式开启时依赖 mock 数据
- 演示模式仍保留（录屏/现场演示均可），入口在问答页右上角

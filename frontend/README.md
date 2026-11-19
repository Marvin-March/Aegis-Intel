# 情报问答前端

智能体驱动的 AI 安全知识情报系统 · 情报问答模块前端演示

## 技术栈

- React 18 + Vite + TypeScript
- Tailwind CSS（深色 SOC 风格）
- lucide-react（图标）
- 无 UI 组件库依赖

## 开发

```bash
# 安装依赖
npm install

# 启动开发服务器（5173 端口，/api 代理至 8000）
npm run dev

# 构建生产版本
npm run build

# 预览构建产物
npm run preview
```

## API 契约

后端接口为 `scripts/api.py`（FastAPI），契约定义在 `src/types/contract.ts`：

- **POST /ask** — 问答主接口（检索 + GLM 生成）
  - 请求：`{query, domain, ai_only, k, with_answer}`
  - 响应：`{route（路由判定字符串）, hits（含 meta）, cards（顶层漏洞卡片）, answer, refused, fabrications, elapsed_s}`
  - 引用约定：答案里 `[n]` = hits 第 n 条；`[卡n]` = cards 第 n 张（均渲染为可点击定位）
- **POST /search** — 只检索不生成（响应 = /ask 去掉 answer/refused/fabrications）
  - 推荐交互流：先 /search 渲染检索过程可视化 → 再 /ask 拿答案（前端已按此两段式实现）
- **GET /health** — 服务状态 `{status, model, store_count, uptime_s}`，前端启动探活
- **GET /related?cve_ids=a,b** — 关联文章反查（卡片区「相关分析文章」折叠面板，零 LLM 成本）

**旧端点状态**（2026-10-10 裁决 b）：`/api/stats /api/runs /api/collect` 后端暂未提供——真实模式下数据看板与情报监测显示降级提示，mock 模式完整演示；后端补齐后自动接回。

## 对接形态

- **模式 A（生产，同端口）**：`npm run build`（`.env.production` 自动切真实模式）→ `uv run python scripts/api.py` → 打开 `http://localhost:8000`
- **模式 B（开发联调）**：`npm run dev`（5173）+ vite proxy 已配置 `/ask /search /health /related` → `http://127.0.0.1:8000`；dev 默认 mock
- **模式 C（远程）**：设 `VITE_API_BASE=http://<后端IP>:8000` 后 `npm run dev`
- **冷启动**：后端首问需 ~40s（模型加载），ask/search 超时已设 90s

## Mock 模式开关

唯一开关位置：`src/api/client.ts` 中的 `USE_MOCK` 常量

```typescript
const USE_MOCK =
  import.meta.env.VITE_USE_MOCK === 'true' ||
  import.meta.env.VITE_USE_MOCK === undefined;
```

- dev 默认为 `true`（mock 数据集中在 `src/mocks/`，六场景数字均为真实口径）
- `.env.production` 设 `VITE_USE_MOCK=false`，构建产物自动真实模式
- 演示模式内部强制 mock（`forceMock` 参数），不受开关影响

## 演示模式（录屏专用）

问答页右上角「演示模式」按钮进入，服务操作演示视频录制（提交要求第 2 项）。

- **入口**：问答页右上「演示模式」按钮；退出走底部控制条「退出演示」或 **Esc**
- **布局**：进入后隐藏左侧会话栏（全屏专注布局），顶部显示半透明水印「演示模式 · 情报问答」，底部出现演示控制条
- **四幕剧本**（每幕自动完成：清空输入 → 打字机逐字输入 30 字/秒 → 发送 → 完整渲染一轮）：
  1. 第一幕·点查：「CVE-2026-59822 是什么漏洞？有修复建议吗？」
  2. 第二幕·语义：「有哪些针对 MCP 工具链的供应链攻击？」
  3. 第三幕·关联：「这个漏洞有哪些分析文章？」（缝合表 article_cve JOIN 叙事）
  4. 第四幕·诚实拒答：「CVE-2024-3094 是什么漏洞？」（不编造 + NVD 链接）
- **一键连播**：四幕顺序自动播放，幕间停 3 秒；控制条显示「第 x/4 幕」与进度点；四枚单幕按钮可单独重放
- **渲染节奏**（对录屏优化）：stepper 每步停 1 秒、命中列表逐条入场、答案打字机 60 字/秒、CVE 卡片在命中后停 2 秒再入场
- **数据源**：演示模式**强制走 mock**（`ask()` 的 `forceMock` 参数，开关逻辑仍在 `src/api/client.ts` 一处），不受后端/GLM 状态影响，录屏零风险
- **会话隔离**：演示轮次写入独立的「演示模式」会话，不污染用户历史；退出后自动切回原会话

实现位置：驱动器 `src/hooks/useDemoPlayer.ts`，控制条与水印 `src/components/DemoOverlay.tsx`。

## 核心功能

### Tab 1：智能问答
- 会话管理（localStorage 持久化，配额溢出时自动裁剪最旧会话）
- 完整问答流程可视化：意图路由 → 向量召回 → 缝合增强 → GLM 生成
- 检索结果卡片展示（分数条 + 域标签 + CVE 卡片）
- 答案打字机效果 + 引用跳转（`[n]` 命中 / `[卡n]` 卡片）+ 一键复制答案
- 拒答处理（库内无记录/阈值过滤）
- 快捷键：`Enter` 发送 / `Shift+Enter` 换行 / `Ctrl+K` 或 `/` 聚焦输入框 / `Esc` 失焦
- 长对话时提供「回到底部」浮动按钮

### Tab 2：数据看板
- Hero 数字滚动动画
- 域分布环形图（SVG 手绘）
- 三轮验证成绩展示
- 富化率统计
- 流水线示意图

### Tab 3：情报监测
- 采集运行历史表格
- 自动刷新（10 秒间隔）
- 手动触发采集（带确认）
- 运行状态实时更新（running 呼吸动画）

## 目录结构

```text
frontend/
├── src/
│   ├── components/       # React 组件
│   ├── types/           # TypeScript 类型
│   ├── api/             # API 客户端（含 mock 开关）
│   ├── mocks/           # Mock 数据
│   └── utils/           # 工具函数（storage/animation）
├── package.json
├── vite.config.ts       # Vite 配置（代理 + hash 路由）
└── tailwind.config.js   # Tailwind 主题（SOC 风格）
```

## 注意事项

- 使用 hash 路由（FastAPI 静态托管要求）
- 所有 fetch 超时 30 秒
- Mock 数字严格使用真实值（契约要求）
- 组件内禁止硬编码数字（集中在 mocks/）

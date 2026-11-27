# 资产暴露面研判 — 实测报告

日期：2026-11-25 ｜ 代码：`scripts/asset_triage/` ｜ 测试：`tests/test_asset_triage.py`

## 一、结论

需求「接入企业组件与版本清单 → 匹配受影响项 → 生成带证据的工单草稿 → 负责人审批变更」
**在本仓库可以完整实现，已跑通并验证**。

原项目（commit `db6fba4`）只有情报采集、富化、问答，缺三块：企业资产清单表、结构化版本
区间、工单与审批。补齐约 1,600 行代码后，整条链路可执行、可测试、可复核。

## 二、实测数据（全部来自程序输出，非估算）

### 输入

| 项目 | 数量 |
|---|---|
| 企业资产（组件+版本） | 14 条，覆盖 6 个内部 AI 应用 |
| 漏洞公告区间（真实 GHSA API） | 378 条，涉及 10 个组件 |
| 可解析区间 | 376 条 |
| 比对组合 | 527 对 |

资产清单按真实企业形态构造：智能客服中台、知识库问答、内部 Agent 平台、模型体验站、
训练流水线、文档智能体；组件版本取真实发布版本（vllm 0.30.2、langchain 1.3.5、
mlflow 3.15.0、transformers 5.2.0、gradio 6.10.0 等）。

### 产出

| 项目 | 数量 |
|---|---|
| 受影响结论 | 88 条 |
| P1 / P2 / P3 / P4 | 7 / 24 / 38 / 19 |
| critical / high / medium / low | 9 / 37 / 32 / 10 |
| 变更工单草稿 | 6 张（按负责人聚合） |

按应用分布：训练流水线 45、智能客服中台 29、知识库问答 6、模型体验站 4、
内部Agent平台 3、文档智能体 1。

按组件分布：mlflow 37、transformers 19、vllm 15、torch 9、gradio 3、
litellm 2、langchain 1、fastmcp 1、langchain-anthropic 1。

### 工单状态（演示了完整状态机）

| 状态 | 数量 | 含义 |
|---|---|---|
| draft | 4 | 待提交 |
| closed | 1 | 已批准并完成升级、关闭 |
| rejected | 1 | 审批时证据失效，自动驳回 |
| **合计** | **6** | |

状态流转实测：`draft → pending_approval → approved → closed`，
以及 `pending_approval → rejected`（证据失效自动触发）。

## 三、正确性验证

### 1. 版本边界（漏报/误报双向）

| 资产 | 版本 | 公告区间 | 期望 | 结果 |
|---|---|---|---|---|
| AI-RAG-PROD-01 langchain | 1.3.9 | `<= 1.3.8` | 不命中 | ✅ 未命中 |
| AI-CS-PROD-02 langchain | 1.3.5 | `<= 1.3.8` | 命中 | ✅ 命中 |
| AI-TRAIN-STG-02 transformers | 4.48.0 | `>= 4.49.0, <= 5.8.1` | 不命中 | ✅ 未命中 |
| AI-CS-PROD-03 transformers | 5.2.0 | `>= 4.49.0, <= 5.8.1` | 命中 | ✅ 命中 |

**1.3.9 不误报、1.3.5 不漏报**——1.3.9 正是 CVE-2026-55443 的修复版本
（GHSA-gr75-jv2w-4656，`first_patched=1.3.9`）。

### 2. 证据可溯源

每条结论都带：安装版本、原始区间、归一化区间、修复版本、公告 URL、SHA-256 证据指纹。
工单里可直接点开厂商公告原文核对。

### 3. 审批安全（三条硬约束实测）

| 场景 | 期望 | 结果 |
|---|---|---|
| 非指定审批人签字 | 拒绝 | ✅ `PermissionError: 审批人不匹配` |
| 审批不填意见 | 拒绝 | ✅ `审批必须填写意见` |
| 已批准的工单重复审批 | 拒绝 | ✅ `当前状态 approved 不可审批` |
| 资产已升级后审批旧工单 | 自动驳回 | ✅ `证据已失效，工单自动驳回：版本已变更为 6.16.0（取证时为 6.10.0）` |
| 无审批人提交 | 拒绝 | ✅ 测试覆盖 |
| 已提交工单被草稿覆盖 | 拒绝 | ✅ 测试覆盖 |

第 4 条是本次实现最关键的设计：审批时重算证据，防止审批人为已经失效的结论签字。

## 四、测试

```
58 passed in 0.55s
```

其中新增 `tests/test_asset_triage.py` **44 项**，原项目既有测试 14 项全部通过
（未破坏原功能）。

新增测试覆盖：PEP 440 边界 10 项、npm caret/tilde/连字符 8 项、prerelease 不截断、
不可解析区间/版本必须抛错、跨生态同名包不合并、优先级规则 5 项、
匹配与去重 4 项、工单审批 8 项（含证据失效）。

## 五、能力边界（未实现，需企业侧配合）

| 未实现 | 原因 | 接入方式 |
|---|---|---|
| 自动发现内网资产 | 需网络扫描授权与 CMDB 访问 | 接 CMDB / 漏洞扫描器导出，走同一 `import` 接口 |
| 直连 ServiceNow / Jira / 飞书审批 | 需企业凭据与字段映射 | 工单导出 JSON/Markdown，加一个 connector 即可 |
| 供应链投毒、0day 的语义判断 | 版本区间比对不覆盖此类 | 走原项目的 LLM 富化与问答链路 |
| 实际执行升级 | 超出情报系统职责 | 审批通过后交由发布系统 |

## 六、如何复现

```bash
cd Aegis-Intel
python scripts/asset_triage_cli.py --db demo/triage.sqlite import demo/assets.csv
python scripts/asset_triage_cli.py --db demo/triage.sqlite sync --source ghsa --max-pages 2
python scripts/asset_triage_cli.py --db demo/triage.sqlite match --out-dir demo
python scripts/asset_triage_cli.py --db demo/triage.sqlite draft --approver 周敏 --actor 系统
python scripts/asset_triage_cli.py --db demo/triage.sqlite submit --ticket <TICKET> --actor 李娜
python scripts/asset_triage_cli.py --db demo/triage.sqlite decide --ticket <TICKET> --approver 周敏 --approve --comment "同意"
```

同步步骤需外网访问 `api.github.com`。内网环境用 `sync --from-file advisories.json` 走离线导出件。

注意：`sync` 拉的是**当时**的 GHSA 数据，重跑得到的公告条数会随上游变化，
上述 378 条是 2026-11-25 的快照。

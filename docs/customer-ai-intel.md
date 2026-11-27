# 客户 AI 组件监控与重点情报推送

流程：**采集客户 AI 组件 → 人工确认实际版本 → 匹配公告 → 推送给对应客户**。

## 1. 采集客户组件

默认目录包含 AI 安全工具和 AI 基础设施。例如 NeMo Guardrails、LLM Guard、Guardrails AI，
以及 vLLM、LiteLLM、LangChain 与 MCP SDK。用 `--category security` 只采集 AI 安全工具，
用 `--catalog 路径` 使用自己的目录。识别按包生态与包名进行，普通依赖不会录入。

```bash
python -m pip install packaging requests
python scripts/customer_intel_cli.py collect --customer acme --deployment ai-api-prod
python scripts/asset_triage_cli.py review-export --scope acme/ai-api-prod --out data/acme-review.csv
# 填写确认、驳回或补录，核实版本与归属后保存为 UTF-8 CSV
python scripts/asset_triage_cli.py review-apply data/acme-review.csv --actor reviewer
```

- 可选 `--python-site 路径` 指定本机虚拟环境，或用 `--npm-lock package-lock.json` 采集 npm。
- 其他机器可用原来的 `discover --report-only` 生成报告，再用 `collect --from-report 报告.json` 导入。
- 同一客户的不同部署使用不同的 `--deployment`。候选实际存入 `客户ID/部署ID`，导出审核表时按这个名称筛选。
- 资产未被采集到时可在审核表中补录，把 `action` 填为 `add`，`scope` 填相同部署标识。
  包名需在本次使用的 AI 组件目录中才会参与推送。
- 复采发现版本变化或已采集组件从该环境消失时，候选回到待审核，期间暂停该部署的推送。
  导入其他机器的报告时，仅对报告中带有观测记录的包生态执行消失复核。

## 2. 获取重点公告并预演

```bash
python scripts/customer_intel_cli.py sync --customer acme --source ghsa
python scripts/customer_intel_cli.py push --customer acme --platform wecom
```

`sync --from-file 公告.json` 可离线导入。线上同步会把已确认的组件包名发给选定的公开情报源，
客户 ID、安装版本和负责人不随请求发送。若已有结构化公告集，可直接用共用 SQLite 跑预演。

筛选条件是**已确认的客户组件、相同包生态、安装版本确实落在公告区间**。优先推送 KEV，
其余默认要求 CVSS ≥ 7。缺评分时参考公告的高危或严重等级。公告区间无效会计入
`unparsed_pairs` 并留待人工处理。首轮可回溯历史公告，`--since-days N` 可限制非 KEV 公告的日期。

## 3. 发给客户对应的群机器人

为客户单独创建 `acme.env`，内容如下。

```dotenv
AEGIS_CUSTOMER_ID=acme
WECOM_WEBHOOK_URL=
FEISHU_WEBHOOK_URL=
FEISHU_SIGN_SECRET=
DINGTALK_WEBHOOK_URL=
DINGTALK_SIGN_SECRET=
```

```bash
# 预演同一目标，并以该目标的发送记录去重
python scripts/customer_intel_cli.py push --customer acme --platform wecom --env-file acme.env
# 确认内容与目标群后执行
python scripts/customer_intel_cli.py push --customer acme --platform wecom --env-file acme.env --send
```

推送包含组件、安装版本、受影响区间、修复版本和公告原文，消息不包含主机路径、负责人或部署名称。
同一客户、同一接收端、同一风险证据组合只发送一次。如果修复版本、区间或 KEV 状态改变，
新证据可独立触发通知。结果不明确时保留发送记录供人工核对。

定时任务可依次调用 `sync` 和 `push --send`。发现与复核仍可单独执行。

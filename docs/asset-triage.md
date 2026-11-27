# 资产暴露面研判（Asset Triage）

把 Aegis Intel 的情报能力，接到企业真实在用的组件与版本上，一路走到「负责人审批变更」。

## 为什么需要这一层

原项目解决的是「世界上有哪些 AI 相关漏洞」；企业真正要回答的是另一个问题：

> 我们哪个应用、哪个环境、哪台机器上装的哪个版本，中了哪条漏洞？谁负责改？谁敢签字？

这两件事之间缺三样东西：**企业资产清单**、**结构化版本区间**、**可审批的变更单**。
本模块补齐这三样。

## 能力边界（先说清楚不能做什么）

| 能做 | 不能做（需要企业侧配合） |
|---|---|
| 读取平台台账、SBOM、pip freeze，或本机采集后人工确认 | 跨主机资产覆盖依赖各主机采集或企业资产台账 |
| 与 GHSA / OSV 的结构化版本区间做确定性比对 | 供应链投毒、0day 的语义级判断 |
| 生成带证据指纹与原文链接的变更工单草稿 | 直接调用 ServiceNow / Jira / 飞书审批 API（需凭据） |
| 负责人/审批人角色校验、证据失效自动驳回 | 替代企业既有审批制度 |

## 四段流水线

```text
① 清单接入            ② 区间同步            ③ 确定性比对           ④ 工单与审批
CSV/JSON 台账    →   GHSA / OSV        →   生态+包名+版本    →   按 owner 聚合
CycloneDX SBOM       结构化 ranges         落在区间内             证据指纹
pip freeze           归一化为 PEP440       （不可解析即失败）      状态机 + 审计
```

### ① 清单接入 `ingest.py`

三种入口，统一产出 `Asset`：

- **平台台账**：CSV/JSON，表头做中英文别名归一（`组件/包名/package/name` 等价）；
- **SBOM**：CycloneDX 1.4/1.5，优先解析 `purl`（`pkg:pypi/vllm@0.30.2`），
  从真实构建产物直接取版本，不靠人填；
- **环境探测**：`pip freeze` / `requirements.txt`，取运行实例上实际安装的版本。

缺版本的行**显式拒收并报告**——没有版本就无法做区间比对，静默接受只会制造假阴性。

### ② 区间同步 `sources.py`

原项目把 OSV 的 `ranges` 丢掉了，只留正文，`vuln_meta.affected_versions` 也只是
`影响 <=1.82.4；升级 1.84.0 修复` 这样的自然语言。机器比对必须拿到原语：

```python
{"ecosystem": "pypi", "package": "mlflow",
 "range_raw": ">= 3.12.0rc0, < 3.17.0", "first_patched": "3.17.0"}
```

GHSA 提供 `vulnerable_version_range` + `first_patched_version`，是最省事的来源；
OSV 的 `events[{introduced, fixed}]` 由 `osv_events_to_range()` 转换。

### ③ 确定性比对 `matcher.py`

三条件同时成立才算命中，任一不满足即不报：

1. 生态 + 包名归一后相等（**不同生态的同名包绝不合并**）；
2. 资产版本可解析，且满足区间；
3. 区间可解析——**不可解析一律 `unparsed`，既不算命中也不算未命中**。

第 3 条是防误报的关键：如果区间解析失败就当「未命中」，会漏掉真实风险；
当成「命中」则制造噪音。正确做法是抛出来交给人看。

`normalize_range()` 负责把各家写法归一成 PEP 440 specifier：

| 原始写法 | 归一化结果 |
|---|---|
| `<= 1.3.8` | `<=1.3.8` |
| `>= 4.49.0, <= 5.8.1` | `>=4.49.0,<=5.8.1` |
| `^1.2.3`（npm） | `>=1.2.3,<2.0.0` |
| `~1.2.3`（npm） | `>=1.2.3,<1.3.0` |
| `1.2.x` | `>=1.2,<1.3` |
| `>=1.0.0 \|\| <0.5.0` | 拒绝（需拆分） |

版本清洗保留 prerelease 段：`3.12.0rc0` 不能截成 `3.12.0`，否则「从预发布起受影响」
会被误判成「从正式版起受影响」。

### ④ 工单与审批 `tickets.py`

工单按 **(负责人, 应用, 环境)** 聚合——变更单是「一个人去改一个环境」，
跨负责人合并会导致无人真正负责。每张单包含：

- 受影响项逐条证据：安装版本、原始区间、归一化区间、修复版本、公告 URL、证据指纹；
- 变更方案：同一组件只升一次，目标取所有命中公告里**最高的**修复版本；
- 回滚方案、验证方案（复跑同一清单确认不再命中）。

审批状态机：

```text
draft ──submit──> pending_approval ──approve──> approved ──close──> closed
                        │
                        └──reject──> rejected ──> (回到 draft 重做)
```

三条硬约束：

1. **无负责人 / 无审批人不得提交**——避免草稿流进审批队列没人认领；
2. **只有指定审批人能签字**，且必须填意见（审计要求）；
3. **审批时重算证据指纹**：资产版本或公告区间在审批期间变了，工单自动 `rejected`。
   审批人不会在过时证据上签字——这是整条链路最容易被忽略、也最容易出事的地方。

## 用法

### 本机采集与人工确认

`discover` 读取执行环境的 Python 包元数据，也可以读取指定虚拟环境的
`site-packages`，或者导入 npm v2/v3 锁文件。加 `--listeners` 会读取操作系统
记录的本机 TCP 监听地址和端口，进程信息取决于当前账号的读取权限。
监听结果是一份独立的 JSON 证据，可用来辅助填写暴露范围。
绑定地址只说明本机监听位置，公网暴露和业务归属由审核人确认。

```bash
python -m pip install packaging
# 使用 --listeners 时另外安装 psutil
python -m pip install psutil

python scripts/asset_triage_cli.py discover --scope ai-api-prod-01 --listeners --report data/discovery.json
python scripts/asset_triage_cli.py review-export --scope ai-api-prod-01 --out data/review.csv
# 用 Excel 或编辑器填写 data/review.csv，保存为 CSV UTF-8
python scripts/asset_triage_cli.py review-apply data/review.csv --actor 张三
python scripts/asset_triage_cli.py sync --from-file advisories.json
python scripts/asset_triage_cli.py match --out-dir data/triage
```

采集其他本机环境时，指定 `--python-site 路径`。Windows 虚拟环境通常对应
`.venv/Lib/site-packages`，Linux 通常对应 `.venv/lib/pythonX.Y/site-packages`。
采集 npm 时用 `--npm-lock package-lock.json`，需要同时采集当前 Python 环境时加
`--python-current`。每个部署实例使用稳定且独立的 `--scope`，定时复采沿用同一标识。
Python 元数据证明包安装在所选环境，npm 锁文件反映构建时选定的版本，实际部署与版本
均由审核人核实。

### 多台主机采集，集中审核

在每台目标机器上按各自的部署标识执行只写报告的模式，然后把报告交给审核人。
报告包含内网主机名、依赖和路径信息，集中端只接收由团队提供的报告。

```bash
# 采集端
python scripts/asset_triage_cli.py discover --scope ai-api-prod-01 --report-only --report ai-api-prod-01.json

# 研判端
python scripts/asset_triage_cli.py discover-import ai-api-prod-01.json --scope ai-api-prod-01
python scripts/asset_triage_cli.py review-export --out data/review.csv
```

集中端按采集时间处理同一部署的报告，重复报告幂等，较旧报告会被拒绝。
同一 scope 由一个采集流程维护，采集主机应使用准确的系统时间。
监听端口保留在原始报告，组件候选及来源入库集中审核。

| 审核操作 | 应填字段 |
|---|---|
| `action=confirm` | 核对 `version`，补齐 `app_name`、`owner`、`environment`、`exposure`、`criticality`；`business_unit` 可选 |
| `action=reject` | 填写 `reason`，保留候选 ID、版本和组件标识对应的原始字段 |
| `action=add` | 新起一行，填写 `scope`、`ecosystem`（`pypi` 或 `npm`）、`component`、版本、业务字段和 `reason`，候选 ID 与审核修订号留空 |
| `action` 留空 | 本次跳过该行 |

`exposure` 可填 `internet/internal/offline`，`criticality` 可填
`low/medium/high/critical`。同组件读到多个版本时保留全部证据，候选版本留空。
冲突、改版本、npm 锁文件确认、手工补录都须说明依据。需要同时保留多个版本时，
按实际部署实例拆分 scope。导出的 `observed_versions` 和 `sources` 用于人工查看，
回填后实际以数据库记录的采集证据为准。

已确认候选才会进入研判。采集证据变化会重新排队，并暂停基于该组件旧版本的匹配与工单审批。
审核表的修订号防止提交过期记录，整张表在同一事务中应用。纠正以往结论可用
`review-export --include-reviewed` 重新导出。某次采集缺少旧组件时保留历史记录，由负责人核实是否下线。
采集和审核全程在本机运行，线上公告同步沿用既有的 `sync` 并需安装 `requests`。

### 直接导入已核实的台账

```bash
# 1. 接入企业清单（三选一）
python scripts/asset_triage_cli.py import assets.csv
python scripts/asset_triage_cli.py import sbom.cdx.json
python scripts/asset_triage_cli.py import pip-freeze.txt

# 2. 同步结构化版本区间
python scripts/asset_triage_cli.py sync --source ghsa --max-pages 2
python scripts/asset_triage_cli.py sync --from-file advisories.json   # 离线内网

# 3. 比对
python scripts/asset_triage_cli.py match --out-dir data/triage

# 4. 生成工单草稿
python scripts/asset_triage_cli.py draft --priority P1,P2 --approver 周敏 --actor 系统

# 5. 审批流
python scripts/asset_triage_cli.py submit --ticket CHG-XXX --actor 李娜 --comment "申请升级"
python scripts/asset_triage_cli.py decide --ticket CHG-XXX --approver 周敏 --approve --comment "同意"
python scripts/asset_triage_cli.py close  --ticket CHG-XXX --actor 李娜 --comment "已完成"
```

默认库是项目共用的 `data/index.sqlite`。候选和审核记录分别保存在 `asset_candidate` 与
`asset_review_event`，已确认资产复用 `asset_component`。

## 优先级规则

`compute_priority(severity, criticality, exposure, kev)`：漏洞严重度 + 资产重要度 +
暴露面加权，映射到 P1–P4。KEV（在野利用）单独抬档——已被实际利用的漏洞是**时间压力**，
即便资产等级不高也不能按 P3/P4 排队。

规则写死在代码里，审批人可以直接复核「为什么这条是 P1」。

## 测试

```bash
python -m pytest tests/test_asset_triage.py tests/test_asset_discovery.py -q
```

回归测试覆盖原有版本比对和审批，以及自动采集、人工审核、版本变化、手工补录、
CSV 批次回滚和真实本机 TCP 监听采集。监听测试需安装 `psutil`。

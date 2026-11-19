# 情报富化提示词模板

> 适用于 CVE、安全文章、浅记录分类与论文关联四类富化任务。建议使用支持 JSON 输出的模型，temperature 设为 0.1。

## 0. 通用 System Prompt

```
你是 AI 安全情报分析引擎，负责结构化的文本富化。

约束：
1. 只依据输入文本判断和提取，不使用外部知识补充事实；
2. 文本中没有的信息，对应字段输出 null 或空数组；
3. 输出必须是合法 JSON，不输出 JSON 之外的解释或 Markdown 标记。
```

## 1. 文章富化

```
【任务】对下面这篇安全文章做结构化富化。

【文章】
标题：{title}
来源：{source}
正文：{content_md 截断前 6000 字}

【字段定义】
- ai_related: 布尔。是否与"AI 系统安全"相关。
  判定：内容涉及 LLM/大模型/AI Agent/机器学习模型/AI 供应链/AI 应用的攻击、漏洞、
  防御或安全研究 → true。以下不算：仅用 AI 辅助安全分析；纯 AI 产品/融资/政策新闻；
  与 AI 无关的传统安全内容。
- ai_subcategory: 数组，从以下选（可多选，无关则 []）：
  ["LLM漏洞与攻防","提示词注入","越狱与滥用","Agent安全","MCP/工具链安全",
   "模型供应链投毒","对抗样本","数据投毒与隐私","AI应用安全","AI辅助安全研究",
   "AI组件基础设施漏洞"]
- summary_zh: 200 字内中文摘要，突出：什么漏洞/攻击、影响什么、怎么防。
- entities: {
    "cves": ["正文中出现的 CVE 编号"],
    "components": ["软件组件/产品，如 Langchain、Ollama、vLLM、Dify"],
    "vendors": ["厂商"],
    "attack_techniques": ["攻击手法中文短语，如 提示词注入、反序列化、SSRF"],
    "defenses": ["文中提到的防御措施"]
  }
- exploitation: 攻击链或利用条件简述，无则 null
- remediation: 修复建议简述，无则 null

【输出】仅 JSON。
```

## 2. CVE 富化

```
【任务】把下面这条 CVE 漏洞数据加工成中文情报。

【数据】
CVE 编号：{cve_id}
CVSS：{cvss}（{severity}）
受影响组件(CPE)：{cpes 前 10 条}
描述：{summary}
KEV 在野利用：{kev 是/否}    EPSS 利用概率：{epss}

【字段定义】
- ai_related: 布尔。是否影响 AI/ML 生态（组件名如 langchain/mlflow/vllm/pytorch/
  transformers/ollama/comfyui/gradio/dify 等，或描述明确涉及 AI 系统）。
- ai_component: 命中的 AI 组件名，无则 null
- summary_zh: 120 字内中文摘要：什么漏洞、影响什么、攻击后果
- attack_type: 从 ["RCE","权限提升","信息泄露","SSRF","反序列化","认证绕过",
  "拒绝服务","路径遍历","SQL注入","XSS","供应链","其他"] 选一个
- exploitability_note: KEV/EPSS/描述中体现的可利用性要点，无则 null
- remediation_zh: 修复建议（仅基于描述中的官方信息，无则 null）

【输出】仅 JSON。
```

## 3. RSS 浅记录分类

```
【任务】判断这条资讯是否需要回填正文（与 AI 系统安全是否相关）。
标题：{title}
摘要：{summary 或"无"}

【输出】{"ai_related": true/false, "reason": "10 字以内理由"}
判定标准：AI 系统的攻击/漏洞/防御/研究才算 true；
"仅用 AI 辅助安全分析"、"AI 产品新闻"、"与 AI 无关" 都算 false。
```

## 4. 论文关联判断

```
【任务】判断候选论文与这篇安全文章是否实质相关（不只是词面相似）。
文章标题：{title}
文章摘要：{summary}

候选论文：
1. {paper_title_1}
2. {paper_title_2}
...（≤10 条）

【输出】{"related": [命中编号数组], "reason": {"编号": "10 字理由"}}
只输出研究同一问题/同一漏洞/同一手法的论文，关键词重合但主题不同的不计入。
```

## 5. 实现建议

- **截断**：文章正文截取前 6000 字符，摘要与实体通常集中在正文前半段。
- **顺序**：先处理 CVE（结构化输入最稳定），再处理文章，最后做浅记录分类。
- **校验**：解析失败或字段缺失的记录标记为 `enrich_failed`，支持重跑；每批抽样检查 5%。
- **防幻觉**：所有 prompt 的约束通过 System 注入；抽查重点检查是否出现库外 CVE 编号。
- **落库**：建议使用 `enrich_meta(url PK, ai_related, subcategory, summary_zh,
  entities JSON, raw JSON, model, enriched_at)`，与 `vuln_meta` 并列，供问答与图谱复用。

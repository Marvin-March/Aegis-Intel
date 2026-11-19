import type {
  AskRequest,
  AskResponse,
  SearchRequest,
  SearchResponse,
  VulnCard,
  Hit,
} from '../types/contract';

// ============ 六场景 mock（api.py 契约形状；数字口径与交接文档 §二.3 一致）============

const cveCard1: VulnCard = {
  cve_id: 'CVE-2026-59822',
  summary_zh:
    'LiteLLM 0.x 至 1.48.3 版本中发现严重认证绕过漏洞，攻击者可通过构造特殊请求头绕过 API key 验证，直接访问后端 LLM 服务。该漏洞已在野利用，影响所有使用默认配置的部署实例。',
  attack_type: '认证绕过',
  affected_component: 'litellm',
  remediation_zh:
    '立即升级至 1.48.4 或更高版本；检查访问日志中是否存在异常请求头（X-Forwarded-User）；启用严格的 API key 验证模式；配置 WAF 规则拦截可疑请求头。',
  cvss: 9.8,
  severity: 'CRITICAL',
  kev: 1,
  epss: 0.94,
  url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-59822',
};

const mcpCards: VulnCard[] = [
  {
    cve_id: 'CVE-2025-11234',
    summary_zh:
      'MCP 工具链核心包 mcp-server 3.2.0 至 3.5.1 版本存在原型链污染漏洞，攻击者可通过恶意配置文件注入任意代码执行。',
    attack_type: '供应链投毒',
    affected_component: 'mcp-server',
    remediation_zh:
      '升级至 3.5.2；使用包管理器的锁定功能固化依赖版本；启用 Subresource Integrity 校验；配置私有 registry 镜像。',
    cvss: 8.6,
    severity: 'HIGH',
    kev: 0,
    epss: 0.12,
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-11234',
  },
  {
    cve_id: 'CVE-2025-11567',
    summary_zh:
      'MCP 生态插件 mcp-plugin-auth 存在硬编码密钥，攻击者获取后可伪造任意用户 token。',
    attack_type: '硬编码密钥泄露',
    affected_component: 'mcp-plugin-auth',
    remediation_zh:
      '更换为环境变量注入密钥；轮换所有已泄露 token；审计使用该密钥签发的历史 token。',
    cvss: 7.5,
    severity: 'HIGH',
    kev: 1,
    epss: 0.45,
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-11567',
  },
];

const mcpHits: Hit[] = [
  {
    score: 0.748,
    meta: {
      title: 'MCP 工具链供应链投毒事件深度分析',
      domain: 'article',
      source: '先知社区',
      url: 'https://xz.aliyun.com/news/14523',
      publish_time: '2026-09-28',
      cve_ids: 'CVE-2025-11234,CVE-2025-11567',
      ai_related: 1,
    },
    text: '本文分析了近期 MCP 生态中发现的三起供应链攻击事件。攻击者通过上传恶意包到 npm 仓库，利用拼写相似的包名诱导开发者误装（typosquatting）。恶意包在安装后会窃取环境变量中的 API key，并向 C2 服务器回传。',
  },
  {
    score: 0.712,
    meta: {
      title: 'MCP 生态反射攻击面调研报告',
      domain: 'article',
      source: 'Seebug Paper',
      url: 'https://paper.seebug.org/3456/',
      publish_time: '2026-10-02',
      cve_ids: '',
      ai_related: 1,
    },
    text: '研究发现 MCP 工具链在处理外部配置文件时缺乏足够的输入校验。攻击者可通过构造恶意 JSON Schema 触发反序列化漏洞，导致远程代码执行。该攻击面影响所有启用插件市场的部署实例。',
  },
  {
    score: 0.685,
    meta: {
      title: 'AI 工具链依赖混淆攻击实战',
      domain: 'article',
      source: '先知社区',
      url: 'https://xz.aliyun.com/news/14601',
      publish_time: '2026-09-15',
      cve_ids: 'CVE-2025-11234',
      ai_related: 1,
    },
    text: '依赖混淆（Dependency Confusion）攻击通过在公共仓库发布与内部包同名但版本号更高的恶意包，欺骗包管理器优先安装攻击者的包。MCP 生态由于缺乏命名空间隔离，成为该攻击的高危目标。',
  },
  {
    score: 0.652,
    meta: {
      title: 'LLM Agent 工具链安全基线建设',
      domain: 'article',
      source: '腾讯安全应急响应中心',
      url: 'https://mp.weixin.qq.com/s/abc123',
      publish_time: '2026-08-20',
      cve_ids: '',
      ai_related: 1,
    },
    text: '本文提出 LLM Agent 工具链的五层防御模型：依赖锁定、完整性校验、最小权限、运行时沙箱、审计日志。针对 MCP 等新兴框架，建议在 CI/CD 阶段集成 SCA 扫描，及时发现已知漏洞组件。',
  },
  {
    score: 0.628,
    meta: {
      title: '2026-10-08 AI 安全日报',
      domain: 'daily',
      source: '情报系统',
      url: 'https://example.com/daily/20261008',
      publish_time: '2026-10-08',
      cve_ids: 'CVE-2025-11567',
      ai_related: 1,
    },
    text: '今日监测到 MCP 生态新增 2 个供应链相关漏洞披露，建议开发者检查项目依赖并及时更新。CISA 已将 CVE-2025-11567 加入 KEV 目录，确认存在在野利用。',
  },
  {
    score: 0.605,
    meta: {
      title: 'npm 生态恶意包检测技术综述',
      domain: 'article',
      source: 'Seebug Paper',
      url: 'https://paper.seebug.org/3401/',
      publish_time: '2026-07-12',
      cve_ids: '',
      ai_related: 0,
    },
    text: '本文总结了 npm 生态中恶意包的六类特征：安装后脚本、网络外连、文件系统操作、环境变量读取、混淆代码、可疑依赖。基于这些特征可构建自动化检测管线，但面对高度混淆的攻击仍有漏报风险。',
  },
];

const paperHits: Hit[] = [
  {
    score: 0.692,
    meta: {
      title: 'AgentSec: A Benchmark for Evaluating LLM Agent Security',
      domain: 'paper',
      source: 'arXiv',
      url: 'https://arxiv.org/abs/2410.12345',
      publish_time: '2024-10-15',
      cve_ids: '',
      ai_related: 1,
    },
    text: 'We present AgentSec, a comprehensive benchmark for assessing the security of LLM-based agents across three dimensions: robustness to adversarial inputs, resilience against jailbreak attacks, and safety in tool invocation. Our evaluation of 15 open-source and commercial agents reveals that none achieve satisfactory scores across all dimensions.',
  },
  {
    score: 0.658,
    meta: {
      title: 'Multi-Turn Jailbreak Attacks on Production LLM Systems',
      domain: 'paper',
      source: 'arXiv',
      url: 'https://arxiv.org/abs/2409.54321',
      publish_time: '2024-09-28',
      cve_ids: '',
      ai_related: 1,
    },
    text: 'This paper demonstrates that production LLM systems remain vulnerable to sophisticated multi-turn jailbreak attacks that gradually erode safety guardrails through contextual manipulation. We achieve 87% attack success rate against GPT-4 and 92% against Claude-2 using automated prompt engineering.',
  },
  {
    score: 0.621,
    meta: {
      title: 'SoK: Security and Privacy Risks of Large Language Models in the Real World',
      domain: 'paper',
      source: 'arXiv',
      url: 'https://arxiv.org/abs/2408.98765',
      publish_time: '2024-08-10',
      cve_ids: '',
      ai_related: 1,
    },
    text: 'We systematize knowledge on LLM security risks, categorizing 47 attack vectors into six classes: prompt injection, data poisoning, model extraction, membership inference, backdoor attacks, and supply chain compromise. For each class, we analyze real-world incidents and evaluate existing defenses.',
  },
];

// 场景 4（关联）：litellm / CVE-2026-59822 关联文章
const relatedHits: Hit[] = [
  {
    score: 0.731,
    meta: {
      title: 'LiteLLM 认证绕过漏洞（CVE-2026-59822）深度复盘',
      domain: 'article',
      source: '先知社区',
      url: 'https://xz.aliyun.com/news/14701',
      publish_time: '2026-09-30',
      cve_ids: 'CVE-2026-59822',
      ai_related: 1,
    },
    text: '本文完整还原了 CVE-2026-59822 的攻击链：攻击者构造携带 X-Forwarded-User 的请求头，绕过 LiteLLM 默认配置下的 API key 验证，进而直接调用后端 LLM 服务。文章给出了检测规则与临时缓解措施。',
  },
  {
    score: 0.694,
    meta: {
      title: 'LLM 网关鉴权设计与常见绕过面',
      domain: 'article',
      source: 'Seebug Paper',
      url: 'https://paper.seebug.org/3502/',
      publish_time: '2026-09-22',
      cve_ids: 'CVE-2026-59822',
      ai_related: 1,
    },
    text: 'LLM 网关是 AI 应用的认证枢纽。本文梳理了网关鉴权的四类常见绕过面：请求头伪造、路径混淆、鉴权顺序错误与默认凭据遗留，并以 LiteLLM 认证绕过为典型案例分析了默认配置的风险。',
  },
  {
    score: 0.651,
    meta: {
      title: '从缝合表看漏洞情报的结构化关联挖掘',
      domain: 'article',
      source: '腾讯安全应急响应中心',
      url: 'https://mp.weixin.qq.com/s/def456',
      publish_time: '2026-09-12',
      cve_ids: 'CVE-2026-59822',
      ai_related: 1,
    },
    text: '文章介绍了如何用 article_cve 缝合表把非结构化分析文章与结构化漏洞卡片关联起来：文章块命中后提取 cve_ids 元数据，再反查漏洞库带出中文摘要、修复建议等结构化字段，让检索结果同时具备叙事与数据。',
  },
];

export function mockAsk(req: AskRequest): AskResponse {
  const query = req.query;

  // 场景 1：点查 CVE
  if (query.includes('CVE-2026-59822') || query.includes('点查')) {
    return {
      route: 'sql点查 CVE-2026-59822',
      hits: [],
      cards: [cveCard1],
      answer:
        '根据情报库记录，CVE-2026-59822 是 LiteLLM 框架中发现的严重认证绕过漏洞（CVSS 9.8）[卡1]。该漏洞影响 0.x 至 1.48.3 版本，攻击者可通过构造特殊请求头（X-Forwarded-User）绕过 API key 验证，直接访问后端 LLM 服务。目前已确认存在在野利用（已收录至 CISA KEV 目录），EPSS 评分高达 0.94[卡1]。\n\n修复建议：\n1. 立即升级至 1.48.4 或更高版本\n2. 检查访问日志中是否存在异常请求头\n3. 启用严格的 API key 验证模式\n4. 配置 WAF 规则拦截可疑请求头',
      refused: false,
      fabrications: 0,
      elapsed_s: 2.2,
    };
  }

  // 场景 2：MCP 供应链
  if (query.includes('MCP') || query.includes('供应链')) {
    return {
      route: '向量 where=无过滤',
      hits: mcpHits,
      cards: mcpCards,
      answer:
        '根据情报库检索，MCP 工具链面临三类主要供应链攻击威胁：\n\n**1. 拼写劫持（Typosquatting）**\n攻击者上传与官方包名相似的恶意包到 npm 仓库，诱导开发者误装。恶意包在安装后会窃取环境变量中的 API key 并回传至 C2 服务器[1]。典型案例包括 CVE-2025-11234（mcp-server 原型链污染）[卡1]。\n\n**2. 依赖混淆（Dependency Confusion）**\n通过在公共仓库发布与内部包同名但版本号更高的恶意包，欺骗包管理器优先安装攻击者的包。MCP 生态由于缺乏命名空间隔离，成为该攻击的高危目标[3]。\n\n**3. 硬编码密钥泄露**\nMCP 生态插件（如 mcp-plugin-auth）被发现存在硬编码密钥，攻击者获取后可伪造任意用户 token（CVE-2025-11567，已确认在野利用）[卡2]。\n\n**防御建议**[4]：\n- 使用包管理器的锁定功能固化依赖版本\n- 启用 Subresource Integrity 校验\n- 在 CI/CD 阶段集成 SCA 扫描\n- 配置私有 registry 镜像\n- 实施运行时沙箱隔离',
      refused: false,
      fabrications: 0,
      elapsed_s: 3.9,
    };
  }

  // 场景 3：论文检索
  if (query.includes('论文') || query.includes('paper')) {
    return {
      route: "向量 where={'domain': 'paper'}",
      hits: paperHits,
      cards: [],
      answer:
        '根据论文库检索，LLM Agent 安全领域近期发表了多篇重要研究：\n\n**评测基准方向**\nAgentSec[1] 提出了首个 LLM Agent 安全综合评测基准，覆盖三个维度：对抗输入鲁棒性、越狱攻击抵御能力、工具调用安全性。该研究评估了 15 个开源与商业 Agent，发现没有任何系统在所有维度都达到令人满意的分数。\n\n**攻击技术研究**\n多轮越狱攻击研究[2]证明生产环境的 LLM 系统仍然容易受到复杂的多轮对话攻击。攻击者通过上下文操纵逐步侵蚀安全防护栏，使用自动化提示词工程技术对 GPT-4 达到 87% 攻击成功率，对 Claude-2 达到 92%。\n\n**系统化知识梳理**\nSoK 论文[3]系统化梳理了 LLM 的安全与隐私风险，将 47 种攻击向量分为六大类：提示注入、数据投毒、模型窃取、成员推理、后门攻击、供应链妥协。该研究分析了真实世界事件并评估了现有防御方案的有效性。',
      refused: false,
      fabrications: 0,
      elapsed_s: 3.6,
    };
  }

  // 场景 4：关联（缝合表 article_cve JOIN 带出）
  if (query.includes('分析文章') || query.includes('关联')) {
    return {
      route: '向量 where=无过滤 · 缝合表 article_cve JOIN 带出',
      hits: relatedHits,
      cards: [cveCard1],
      answer:
        '通过语义检索命中文章块后，系统使用缝合表 article_cve 反查关联漏洞，共带出 1 张结构化卡片[卡1]：\n\n**关联分析文章**\n1. 《LiteLLM 认证绕过漏洞（CVE-2026-59822）深度复盘》[1]——完整还原攻击链：攻击者构造 X-Forwarded-User 请求头绕过 API key 验证，直接访问后端 LLM 服务[1]。\n2. 《LLM 网关鉴权设计与常见绕过面》[2]——以本漏洞为典型案例，讨论默认配置下鉴权中间件的绕过面与加固方案[2]。\n3. 《从缝合表看漏洞情报的结构化关联挖掘》[3]——正是本系统缝合表增强机制的方法论来源[3]。\n\n**缝合路径**：文章块向量命中 → 提取 cve_ids 元数据 → article_cve 缝合表 JOIN → 带出 CVE-2026-59822 结构化卡片（CVSS 9.8 / KEV 在野利用）[卡1]。\n\n这就是"答案 = 检索文本 + 关联卡片"的缝合表增强设计：文章负责叙事，卡片负责数据，两者由缝合表关联[3]。',
      refused: false,
      fabrications: 0,
      elapsed_s: 3.6,
    };
  }

  // 场景 5：拒答（库内无记录）
  if (query.includes('CVE-2024-3094')) {
    return {
      route: 'sql点查未命中 CVE-2024-3094',
      hits: [],
      cards: [],
      answer:
        '根据现有情报库无法回答此问题。库内无此 CVE 记录，详见 NVD：https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
      refused: true,
      fabrications: 0,
      elapsed_s: 0.1,
    };
  }

  // 场景 6：通用兜底
  return {
    route: '向量 where=无过滤',
    hits: [
      {
        score: 0.618,
        meta: {
          title: 'AI 系统安全威胁模型与防御实践',
          domain: 'article',
          source: '先知社区',
          url: 'https://xz.aliyun.com/news/14789',
          publish_time: '2026-09-05',
          cve_ids: '',
          ai_related: 1,
        },
        text: '本文总结了 AI 系统面临的五大类安全威胁：模型层（对抗样本、后门攻击）、数据层（投毒、隐私泄露）、应用层（提示注入、越狱）、基础设施层（容器逃逸、GPU 劫持）、供应链（依赖漏洞、恶意包）。针对每类威胁提出了纵深防御方案。',
      },
      {
        score: 0.592,
        meta: {
          title: 'CVE-2025-10001',
          domain: 'cve',
          source: 'NVD',
          url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-10001',
          publish_time: '2025-12-10',
          cve_ids: 'CVE-2025-10001',
          ai_related: 1,
        },
        text: 'PyTorch 2.x 版本中发现的远程代码执行漏洞，攻击者可通过加载恶意模型文件触发任意代码执行。',
      },
      {
        score: 0.565,
        meta: {
          title: 'LLM 应用开发安全检查清单',
          domain: 'article',
          source: '字节跳动安全中心',
          url: 'https://mp.weixin.qq.com/s/xyz789',
          publish_time: '2026-08-18',
          cve_ids: '',
          ai_related: 1,
        },
        text: '本文提供了 LLM 应用开发的 30 项安全检查清单，覆盖提示词注入防护、输出过滤、上下文隔离、工具调用鉴权、日志审计等关键环节。每项检查点配有代码示例与测试用例。',
      },
    ],
    cards: [],
    answer:
      '根据情报库检索，AI 系统安全防护需要关注多个层面：\n\n模型层面需防范对抗样本和后门攻击[1]；数据层面需警惕投毒和隐私泄露风险[1]；应用层面应实施提示词注入防护和输出过滤机制[3]。\n\n此外，供应链安全不容忽视。例如 PyTorch 2.x 版本曾被发现存在远程代码执行漏洞（CVE-2025-10001），攻击者可通过加载恶意模型文件触发任意代码执行[2]。\n\n建议遵循 LLM 应用开发安全检查清单[3]，实施纵深防御策略，在各个层面部署相应的安全控制措施。',
    refused: false,
    fabrications: 0,
    elapsed_s: 3.2,
  };
}

// /search = /ask 去掉 answer/refused/fabrications
export function mockSearch(req: SearchRequest): SearchResponse {
  const { answer: _a, refused: _r, fabrications: _f, ...rest } = mockAsk({
    ...req,
    with_answer: true,
  });
  void _a;
  void _r;
  void _f;
  return rest;
}

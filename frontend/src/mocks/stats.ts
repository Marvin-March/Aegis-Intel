import type { HealthResponse, StatsResponse } from '../types/contract';

// /health mock（真实模式来自 api.py；store_count 与口径表一致）
export function mockHealth(): HealthResponse {
  return {
    status: 'ok',
    model: 'WeMM-Embedding-4B',
    store_count: 54297,
    uptime_s: 1234,
  };
}

export function mockStats(): StatsResponse {
  return {
    vector: {
      count: 54297,
      dim: 2560,
      metric: 'cosine',
      model: 'WeMM-Embedding-4B',
      domains: {
        cve: 35573,
        article: 18444,
        paper: 244,
        daily: 36,
      },
    },
    sqlite: {
      records: 30204,
      ai_vulns: 1459,
      article_cve: 729,
      paper_link: 124,
      affected_component: 1104,
      affected_versions: 434,
      cpes: 8600,
      near7d: 312,
      latest_date: '2026-10-14',
      export_md: 26560,
      cve_enrich_rate: 0.977,
      article_enrich_rate: 0.988,
    },
    collectors: {
      count: 7,
      rss_sources: 906,
    },
    dist: {
      attack: { DoS: 424, '认证绕过': 192, RCE: 180, '信息泄露': 175, '路径遍历': 129, SSRF: 85, '反序列化': 65, XSS: 40, '权限提升': 32, 'SQL注入': 24, '代码注入': 4, '命令注入': 4, '供应链': 5, 'AI投毒与隐私': 1, '其他': 129 },
      severity: { CRITICAL: 2891, HIGH: 11204, MEDIUM: 9876, LOW: 1904, UNKNOWN: 796 },
      kev: 1648,
      // crawl_time 入库口径（2026-10-16）：与 today.recent_days 同源，尾部对齐真实数据
      days: Array.from({ length: 30 }, (_, i) => {
        const d = new Date('2026-10-16T00:00:00');
        d.setDate(d.getDate() - (29 - i));
        const key = d.toISOString().slice(0, 10);
        const real: Record<string, number> = {
          '2026-10-13': 689, '2026-10-14': 62, '2026-10-15': 0, '2026-10-16': 92,
        };
        return { day: key, count: real[key] ?? (i % 4 === 0 ? 12 : 30 + ((i * 17) % 240)) };
      }),
      article_sources: [
        { source: 'freebuf', count: 512 }, { source: '先知社区', count: 388 },
        { source: 'seebug', count: 245 }, { source: '腾讯安全应急响应中心', count: 156 },
        { source: '奇安信攻防社区', count: 121 }, { source: '安全客', count: 98 },
        { source: 'The Hacker News', count: 70 }, { source: '补天平台', count: 64 },
        { source: '青藤云安全', count: 52 }, { source: '绿盟科技', count: 47 },
        { source: '嘶吼', count: 41 }, { source: 'FreeBuf企业版', count: 33 },
        { source: '安全内参', count: 28 }, { source: '微步在线', count: 24 },
        { source: '腾讯玄武实验室', count: 19 }, { source: '阿里云安全', count: 16 },
        { source: '安全客-每日', count: 12 }, { source: 'NVD Daily', count: 9 },
        { source: 'CISA Advisories', count: 7 }, { source: '未知', count: 41 },
      ],
      paper_sources: [
        { source: 'arxiv', count: 289 }, { source: 'usenix', count: 4 }, { source: 'ccs', count: 3 },
      ],
    },
    // 今日采集速报（2026-10-16）：crawl_time 入库口径
    top_threats: [
      {
        cve_id: 'CVE-2026-59822',
        cvss: 8.2,
        kev: true,
        epss: 0.00836,
        summary: 'LiteLLM MCP 端点认证绕过（OAuth2 回退缺陷），未认证攻击者可访问 MCP 工具',
        why: 'KEV 在野利用 + CVSS 8.2，应急优先级最高',
      },
      {
        cve_id: 'CVE-2026-37004',
        cvss: 9.8,
        kev: false,
        epss: 0.00799,
        summary: 'BerriAI litellm <=1.82.4 /prompts/test 端点 SSTI，未认证远程执行任意 OS 命令',
        why: 'CVSS 9.8 严重级，EPSS 0.008（被实际利用概率较低），建议纳入关注',
      },
      {
        cve_id: 'CVE-2026-22686',
        cvss: 10.0,
        kev: false,
        epss: 0.00753,
        summary: 'enclave-vm 2.7.0 之前沙箱逃逸：沿原型链获取宿主 Function 构造函数执行任意代码',
        why: 'CVSS 10.0 严重级，尚未见在野利用，建议纳入关注',
      },
    ],
    today: {
      date: '2026-10-16',
      total: 92,
      by_type: { 'CVE 漏洞': 43, 'RSS 文章': 35, '论文': 6, '安全通告': 5, '深度文章': 3 },
      by_source: [
        { source: 'nvd', count: 28 }, { source: 'The Hacker News', count: 13 },
        { source: 'cnnvd', count: 10 }, { source: 'BleepingComputer', count: 9 },
        { source: 'arxiv', count: 6 }, { source: 'osv', count: 5 },
        { source: 'kev', count: 5 }, { source: '先知社区', count: 3 },
      ],
      recent_days: [
        { day: '2026-10-10', count: 0 }, { day: '2026-10-11', count: 0 },
        { day: '2026-10-12', count: 0 }, { day: '2026-10-13', count: 689 },
        { day: '2026-10-14', count: 62 }, { day: '2026-10-15', count: 0 },
        { day: '2026-10-16', count: 92 },
      ],
    },
    bench: {
      smoke: '10/10',
      large: '39/39',
      cosine_gate: '10/10 ≥0.99',
      top1_range: '0.515~0.798',
      threshold: 0.3,
      latency_cpu: '0.5~2.7s',
    },
  };
}

// 看板下钻 mock（2026-10-16）：按 severity/attack 过滤内置样例
export function mockVulns(params: { severity?: string; attack?: string; limit?: number }) {
  const all = [
    { cve_id: 'CVE-2026-93952', cvss: 10.0, severity: 'CRITICAL', kev: true, publish_time: '2026-10-13', attack_type: '认证绕过', summary_zh: 'Arista VeloCloud Orchestrator 特权功能未授权访问', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-93952' },
    { cve_id: 'CVE-2026-59822', cvss: 8.2, severity: 'HIGH', kev: true, publish_time: '2026-09-17', attack_type: '认证绕过', summary_zh: 'LiteLLM MCP 端点认证绕过（OAuth2 回退缺陷）', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-59822' },
    { cve_id: 'CVE-2026-35029', cvss: 9.1, severity: 'CRITICAL', kev: false, publish_time: '2026-09-02', attack_type: 'RCE', summary_zh: 'LiteLLM /config/update 未鉴权导致 RCE', url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-35029' },
  ];
  const vulns = all.filter((v) => (!params.severity || v.severity === params.severity.toUpperCase())
    && (!params.attack || v.attack_type === params.attack)).slice(0, params.limit ?? 30);
  return { total: vulns.length, vulns };
}

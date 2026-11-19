import type { RelatedResponse } from '../types/contract';

// ============ /related mock：卡片关联文章反查（缝合表 article_cve）============

export function mockRelated(cveIds: string[]): RelatedResponse {
  const wanted = new Set(cveIds);
  const articles: RelatedResponse['articles'] = [];

  if (wanted.has('CVE-2026-59822')) {
    articles.push(
      {
        cve_id: 'CVE-2026-59822',
        title: 'LiteLLM 认证绕过漏洞（CVE-2026-59822）深度复盘',
        url: 'https://xz.aliyun.com/news/14701',
        source: '先知社区',
        publish_time: '2026-09-30',
      },
      {
        cve_id: 'CVE-2026-59822',
        title: 'LLM 网关鉴权设计与常见绕过面',
        url: 'https://paper.seebug.org/3502/',
        source: 'Seebug Paper',
        publish_time: '2026-09-22',
      },
      {
        cve_id: 'CVE-2026-59822',
        title: '从缝合表看漏洞情报的结构化关联挖掘',
        url: 'https://mp.weixin.qq.com/s/def456',
        source: '腾讯安全应急响应中心',
        publish_time: '2026-09-12',
      }
    );
  }

  if (wanted.has('CVE-2025-11234')) {
    articles.push({
      cve_id: 'CVE-2025-11234',
      title: 'MCP 工具链供应链投毒事件深度分析',
      url: 'https://xz.aliyun.com/news/14523',
      source: '先知社区',
      publish_time: '2026-09-28',
    });
  }

  if (wanted.has('CVE-2025-11567')) {
    articles.push({
      cve_id: 'CVE-2025-11567',
      title: '2026-10-08 AI 安全日报',
      url: 'https://example.com/daily/20261008',
      source: '情报系统',
      publish_time: '2026-10-08',
    });
  }

  return { articles };
}

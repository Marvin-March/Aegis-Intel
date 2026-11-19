import type {
  AskRequest,
  AskResponse,
  SearchRequest,
  SearchResponse,
  HealthResponse,
  RelatedResponse,
  StatsResponse,
  RunsResponse,
  CollectRequest,
  CollectResponse,
  NormalizedHit,
  NormalizedQA,
  RouteBranch,
  VulnCard,
  VulnListResponse,
} from '../types/contract';
import { mockAsk, mockSearch } from '../mocks/ask';
import { mockStats, mockHealth, mockVulns } from '../mocks/stats';
import { mockRuns, mockCollect } from '../mocks/runs';
import { mockRelated } from '../mocks/related';

// ============ MOCK 开关（唯一位置）============
// 默认必须关：undefined 时曾默认开，导致全站跑在 mock 兜底回答上（用户实测
// "无论问什么都一样的回答"）。只有显式 VITE_USE_MOCK=true 才启用演示模式。
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

export const isMockMode = () => USE_MOCK;

// 形态 C 预留：跨机联调时设 VITE_API_BASE=http://<后端IP>:8000，默认空串同源
const API_BASE: string = import.meta.env.VITE_API_BASE ?? '';

// ============ 统一 fetch 封装（超时可分级）============
async function fetchAPI<T>(
  endpoint: string,
  options?: RequestInit,
  timeoutMs = 30000
): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`请求失败: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(timeoutMs >= 120000 ? '请求超时（生成时间过长，请重试）' : `请求超时（${Math.round(timeoutMs / 1000)}秒）`);
      }
      if (error instanceof TypeError) {
        // fetch 网络层失败（后端未启动 / 连接拒绝）
        throw new Error(`无法连接后端 (${API_BASE || '127.0.0.1:8000'})，请先启动 server`);
      }
      throw error;
    }
    throw new Error('未知错误');
  }
}

// ============ 归一化：api.py 原始响应 → 组件视图模型 ============

const CVE_RE = /CVE-\d{4}-\d{4,7}/;

// meta.cve_ids 后端是字符串（单个/逗号/空格分隔），解析并滤脏（接口约定）
function parseCveIds(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return raw.filter((v): v is string => typeof v === 'string' && CVE_RE.test(v));
  }
  if (typeof raw === 'string') {
    return raw
      .split(/[,\s;、]+/)
      .map((s) => s.trim())
      .filter((s) => CVE_RE.test(s));
  }
  return [];
}

// route 中文字符串 → 分支推断（耦合后端文案，集中在此一处）
function inferBranch(route: string): RouteBranch {
  if (/未命中/.test(route)) return 'point';
  if (/sql点查|SQL\s*点查/i.test(route)) return 'point';
  if (/paper|论文/i.test(route)) return 'paper';
  return 'semantic';
}

function normalizeHit(raw: unknown): NormalizedHit {
  const h = (raw ?? {}) as Record<string, unknown>;
  const meta = (h.meta ?? {}) as Record<string, unknown>;
  return {
    score: typeof h.score === 'number' ? h.score : undefined,
    domain: typeof meta.domain === 'string' ? meta.domain : '',
    title: typeof meta.title === 'string' ? meta.title : '',
    url: typeof meta.url === 'string' ? meta.url : '',
    source: typeof meta.source === 'string' ? meta.source : '',
    publish_time: typeof meta.publish_time === 'string' ? meta.publish_time : '',
    cve_ids: parseCveIds(meta.cve_ids),
    ai_related: meta.ai_related === 1 ? 1 : 0,
    text: typeof h.text === 'string' ? h.text : '',
  };
}

function normalizeCards(raw: unknown): VulnCard[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (c): c is VulnCard => !!c && typeof c === 'object' && typeof (c as VulnCard).cve_id === 'string'
  );
}

export function normalizeQA(
  raw: AskResponse | SearchResponse,
  withAnswer: boolean
): NormalizedQA {
  const routeText = typeof raw?.route === 'string' ? raw.route : '';
  return {
    route: { branch: inferBranch(routeText), reason: routeText },
    hits: (Array.isArray(raw?.hits) ? raw.hits : []).map(normalizeHit),
    cards: normalizeCards(raw?.cards),
    ...(withAnswer
      ? {
          answer: typeof (raw as AskResponse).answer === 'string' ? (raw as AskResponse).answer : '',
          refused: Boolean((raw as AskResponse).refused),
          fabrications: Number((raw as AskResponse).fabrications ?? 0),
          elapsed_s: typeof (raw as AskResponse).elapsed_s === 'number' ? (raw as AskResponse).elapsed_s : undefined,
        }
      : { refused: false, fabrications: 0 }),
  };
}

// ============ API 方法（ask/search 超时 240s：DeepSeek 深度回答实测最长 122.7s）============

export async function searchOnly(
  req: SearchRequest,
  opts?: { forceMock?: boolean }
): Promise<NormalizedQA> {
  if (USE_MOCK || opts?.forceMock) {
    await new Promise((resolve) => setTimeout(resolve, 1200));
    return normalizeQA(mockSearch(req), false);
  }
  const raw = await fetchAPI<SearchResponse>(
    '/search',
    { method: 'POST', body: JSON.stringify(req) },
    240000
  );
  return normalizeQA(raw, false);
}

export async function ask(
  req: AskRequest,
  opts?: { forceMock?: boolean }
): Promise<NormalizedQA> {
  if (USE_MOCK || opts?.forceMock) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    return normalizeQA(mockAsk(req), true);
  }
  const raw = await fetchAPI<AskResponse>(
    '/ask',
    { method: 'POST', body: JSON.stringify(req) },
    240000
  );
  return normalizeQA(raw, true);
}

export async function getHealth(): Promise<HealthResponse> {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    return mockHealth();
  }
  return fetchAPI<HealthResponse>('/health', undefined, 5000);
}

export async function getRelated(cveIds: string[]): Promise<RelatedResponse> {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 600));
    return mockRelated(cveIds);
  }
  return fetchAPI<RelatedResponse>(
    `/related?cve_ids=${encodeURIComponent(cveIds.join(','))}`,
    undefined,
    15000
  );
}

// 看板下钻：严重度/攻击类别 → 漏洞清单（2026-10-16）
export async function getVulns(
  params: { severity?: string; attack?: string; limit?: number } = {}
): Promise<VulnListResponse> {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 300));
    return mockVulns(params);
  }
  const q = new URLSearchParams();
  if (params.severity) q.set('severity', params.severity);
  if (params.attack) q.set('attack', params.attack);
  q.set('limit', String(params.limit ?? 30));
  return fetchAPI<VulnListResponse>(`/api/vulns?${q.toString()}`, undefined, 30000);
}

// ---------- 旧端点（后端补齐前仅 mock 可用）----------

export async function getStats(): Promise<StatsResponse> {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 800));
    return mockStats();
  }
  return fetchAPI<StatsResponse>('/api/stats');
}

export async function getRuns(): Promise<RunsResponse> {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return mockRuns();
  }
  return fetchAPI<RunsResponse>('/api/runs');
}

export async function triggerCollect(
  request: CollectRequest
): Promise<CollectResponse> {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    return mockCollect(request);
  }
  return fetchAPI<CollectResponse>('/api/collect', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

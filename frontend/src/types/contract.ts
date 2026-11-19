// ============ API 契约类型定义 ============
// 2026-10-10 起对齐 scripts/api.py 实际契约（4 端点：/ask /search /health /related）。
// 旧 /api/stats /api/runs /api/collect 后端暂未提供，类型保留供 mock 使用，后端补齐后直接接回。

// ---------- /ask /search ----------

/** 多轮对话历史：前端把本会话最近几轮消息传给后端做实体继承（后端 search.py 路由用） */
export interface HistoryTurn {
  role: 'user' | 'assistant';
  content: string;
  /** assistant 轮：该轮响应的锁定实体（response.cards[0].cve_id），指代短句用它重写查询 */
  cve_id?: string;
}

export interface AskRequest {
  query: string;
  domain?: string | null; // null | 'paper' | 'article' | 'cve'（UI 过滤器已移除，省略=后端默认全量）
  ai_only?: boolean;
  k: number;
  with_answer: boolean;
  history?: HistoryTurn[];
}

export type SearchRequest = Omit<AskRequest, 'with_answer'>;

export interface HitMeta {
  title: string;
  domain: string; // 'cve' | 'article' | 'paper' | 'daily'
  source: string;
  url: string;
  publish_time: string;
  cve_ids: string; // 后端为字符串（如 "CVE-2025-62164"），前端解析
  ai_related: 0 | 1;
}

export interface Hit {
  score: number;
  meta: HitMeta;
  text: string;
}

export interface VulnCard {
  cve_id: string;
  cvss: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  kev: 0 | 1;
  summary_zh: string;
  attack_type: string;
  affected_component: string;
  remediation_zh: string;
  url: string;
  title?: string;
  /** api.py 契约示例未列出，后端有则渲染（防御渲染：缺失隐藏该行） */
  epss?: number;
}

export interface AskResponse {
  route: string; // 如 "向量 where=无过滤" / "sql点查 CVE-xxx" / "sql点查未命中 xxx"
  hits: Hit[];
  cards: VulnCard[];
  answer: string; // [n] = hits 第 n 条；[卡n] = cards 第 n 张
  refused: boolean;
  fabrications: number;
  elapsed_s: number;
}

export type SearchResponse = Omit<AskResponse, 'answer' | 'refused' | 'fabrications'>;

// ---------- /health ----------

export interface HealthResponse {
  status: string;
  model: string;
  store_count: number;
  uptime_s: number;
}

// ---------- /related ----------

export interface RelatedArticle {
  cve_id: string;
  title: string;
  url: string;
  source: string;
  publish_time: string;
}

export interface RelatedResponse {
  articles: RelatedArticle[];
}

// ---------- 旧端点（后端补齐前仅 mock）----------

export interface StatsResponse {
  vector: {
    count: number;
    dim: number;
    metric: string;
    model: string;
    domains: {
      cve: number;
      article: number;
      paper: number;
      daily: number;
    };
  };
  sqlite: {
    records: number;
    ai_vulns: number;
    article_cve: number;
    paper_link: number;
    affected_component: number;
    affected_versions: number;
    cpes: number;
    near7d: number;
    latest_date: string;
    export_md: number;
    cve_enrich_rate: number;
    article_enrich_rate: number;
  };
  collectors: {
    count: number;
    rss_sources: number;
  };
  dist: {
    attack: Record<string, number>;
    severity: Record<string, number>;
    kev: number;
    days: { day: string; count: number }[];
    article_sources: { source: string; count: number }[];
    paper_sources: { source: string; count: number }[];
  };
  // 今日采集速报（2026-10-16）：按入库时间口径，可选字段（后端旧版无此块时降级隐藏面板）
  today?: {
    date: string;
    total: number;
    by_type: Record<string, number>;
    by_source: { source: string; count: number }[];
    recent_days: { day: string; count: number }[];
  };
  // 今日重点关注 Top3（2026-10-16，应急决策）：KEV/CVSS/EPSS 排序的 AI 高危
  top_threats?: {
    cve_id: string;
    cvss: number | null;
    kev: boolean;
    epss: number;
    summary: string;
    why: string;
  }[];
  bench: {
    smoke: string;
    large: string;
    cosine_gate: string;
    top1_range: string;
    threshold: number;
    latency_cpu: string;
  };
}

export interface VulnListItem {
  cve_id: string;
  cvss: number | null;
  severity: string | null;
  kev: boolean;
  publish_time: string;
  attack_type: string;
  summary_zh: string;
  url: string;
}

export interface VulnListResponse {
  total: number;
  vulns: VulnListItem[];
}

export interface RunRecord {
  run_id: string;
  mode: 'daily' | 'manual' | 'backfill';
  started_at: string;
  duration_s: number;
  new_records: number;
  status: 'ok' | 'running' | 'failed';
}

export interface RunsResponse {
  runs: RunRecord[];
}

export interface CollectRequest {
  mode: string;
}

export interface CollectResponse {
  run_id: string;
  started: boolean;
}

// ---------- 归一化视图模型（client.ts 产出，组件只消费该形状）----------

export interface NormalizedHit {
  score?: number;
  domain: string;
  title: string;
  url: string;
  source: string;
  publish_time: string;
  cve_ids: string[];
  ai_related: 0 | 1;
  text: string;
}

export type RouteBranch = 'point' | 'semantic' | 'paper' | 'refuse';

export interface NormalizedQA {
  route: { branch: RouteBranch; reason: string; elapsed_ms?: number };
  hits: NormalizedHit[];
  cards: VulnCard[];
  /** 两段式：/search 阶段无答案 */
  answer?: string;
  refused: boolean;
  fabrications: number;
  elapsed_s?: number;
  /** /ask 阶段失败标记（骨架态显示生成失败） */
  failed?: boolean;
}

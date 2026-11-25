import { useEffect, useState } from 'react';
import { RefreshCw, X, ExternalLink, AlertTriangle, ArrowRight, Sparkles } from 'lucide-react';
import { getStats, getVulns, isMockMode } from '../api/client';
import type { StatsResponse, VulnListResponse } from '../types/contract';
import HeroNumber from './HeroNumber';
import DonutChart from './DonutChart';
import { Panel } from './ui/Panel';
import { Button } from './ui/Button';
import { SeverityBadge, KevBadge } from './ui/Badge';
import { getSeverityMeta } from './ui/tokens';

const CAT_COLORS = [
  '#f43f5e',
  '#38bdf8',
  '#a78bfa',
  '#10b981',
  '#f59e0b',
  '#ec4899',
  '#60a5fa',
  '#fb923c',
];

interface Props {
  onInvestigate?: (cveId: string) => void;
}

export default function StatsTab({ onInvestigate }: Props) {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sel, setSel] = useState<{ severity?: string; attack?: string } | null>(null);
  const [vlist, setVlist] = useState<VulnListResponse | null>(null);
  const [vloading, setVloading] = useState(false);

  const drill = (next: { severity?: string; attack?: string } | null) => {
    setSel((cur) => {
      const same = cur && cur.severity === next?.severity && cur.attack === next?.attack;
      const target = same ? null : next;
      setVlist(null);
      if (target) {
        setVloading(true);
        getVulns(target)
          .then(setVlist)
          .catch(() => setVlist(null))
          .finally(() => setVloading(false));
      }
      return target;
    });
  };

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getStats();
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex items-center gap-2.5 text-xs font-mono text-soc-text-muted">
          <span className="soc-dots">
            <span />
            <span />
            <span />
          </span>
          LOADING TELEMETRY...
        </div>
      </div>
    );
  }

  if (error || !stats) {
    const degraded = !isMockMode();
    return (
      <div className="max-w-lg mx-auto my-20 aegis-surface p-6 text-center space-y-4 animate-fade-in">
        <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto">
          <AlertTriangle size={18} className="text-amber-400" />
        </div>
        <p className="text-xs text-soc-text-secondary leading-relaxed">
          {degraded
            ? '数据看板依赖的 /api/stats 端点后端暂未提供（当前 api.py 提供 /ask /search /health /related）。此页在 mock 模式下可预览完整看板。'
            : error || '加载失败'}
        </p>
        <Button variant="primary" onClick={fetchStats}>
          <RefreshCw size={13} />
          重新加载
        </Button>
      </div>
    );
  }

  const domainData = [
    { label: 'CVE 漏洞', value: stats.vector.domains.cve, color: '#f43f5e' },
    { label: '资讯文章', value: stats.vector.domains.article, color: '#38bdf8' },
    { label: '学术论文', value: stats.vector.domains.paper, color: '#a78bfa' },
    ...(stats.vector.domains.daily > 0
      ? [{ label: '每日简报', value: stats.vector.domains.daily, color: '#10b981' }]
      : []),
  ];

  const dist = (stats as StatsResponse & { dist?: StatsResponse['dist'] }).dist;
  const attackEntries = Object.entries(dist?.attack ?? {}).sort(
    (x, y) => (x[0] === '其他' ? 1 : 0) - (y[0] === '其他' ? 1 : 0) || y[1] - x[1]
  );
  const attackMax = Math.max(...attackEntries.map(([, v]) => v), 1);
  const dayMax = Math.max(...(dist?.days ?? []).map((m) => m.count), 1);
  const artMax = Math.max(...(dist?.article_sources ?? []).map((s) => s.count), 1);
  const papMax = Math.max(...(dist?.paper_sources ?? []).map((s) => s.count), 1);
  const today = (stats as StatsResponse & { today?: StatsResponse['today'] }).today;
  const top = (stats as StatsResponse & { top_threats?: StatsResponse['top_threats'] }).top_threats;
  const todayMax = Math.max(...(today?.by_source ?? []).map((s) => s.count), 1);
  const recMax = Math.max(...(today?.recent_days ?? []).map((m) => m.count), 1);

  return (
    <div className="max-w-6xl mx-auto space-y-5 animate-fade-in">
      {/* Row 1: 6-column KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        <HeroNumber label="向量块总数" value={stats.vector.count} accent="cyan" />
        <HeroNumber label="情报记录数" value={stats.sqlite.records} />
        <HeroNumber label="AI 相关漏洞" value={stats.sqlite.ai_vulns} accent="danger" />
        <HeroNumber label="近 7 天新增" value={stats.sqlite.near7d} accent="success" />
        <HeroNumber label="RSS 订阅源" value={stats.collectors.rss_sources} />
        <HeroNumber label="采集器数量" value={stats.collectors.count} />
      </div>

      {/* Row 2: Priority Top 3 (with AI Investigate button) + Today */}
      {(top && top.length > 0) || today ? (
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
          {top && top.length > 0 && (
            <Panel
              code="PRIORITY"
              title="今日重点关注 Top 3"
              subtitle="按 KEV 在野 / CVSS / EPSS 加权排序"
              className={today ? 'xl:col-span-6' : 'xl:col-span-12'}
              bodyClassName="p-3.5 space-y-2.5"
            >
              {top.map((t, i) => (
                <div
                  key={t.cve_id}
                  className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.025] border border-white/[0.07] hover:border-white/[0.14] transition-colors"
                >
                  <div
                    className={`w-7 h-7 rounded-lg flex-shrink-0 flex items-center justify-center font-mono text-xs font-semibold border ${
                      t.kev
                        ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                        : 'bg-sky-500/15 border-sky-400/35 text-sky-300'
                    }`}
                  >
                    0{i + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                      <span className="text-sky-300 font-semibold">{t.cve_id}</span>
                      <span className="text-slate-300 tabular-nums">CVSS {t.cvss ?? '-'}</span>
                      {t.kev && <KevBadge />}
                      <span className="text-slate-400 tabular-nums">
                        EPSS {(t.epss * 100).toFixed(1)}%
                      </span>
                      {onInvestigate && (
                        <button
                          onClick={() => onInvestigate(t.cve_id)}
                          className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-sky-500/15 hover:bg-sky-400 hover:text-slate-950 border border-sky-400/35 text-sky-300 text-[10px] font-sans font-medium transition-colors"
                        >
                          <Sparkles size={10} />
                          AI 研判
                        </button>
                      )}
                    </div>
                    <p
                      className="text-xs text-slate-300 mt-1.5 leading-relaxed line-clamp-2"
                      title={t.summary}
                    >
                      {t.summary}
                    </p>
                    <p className="text-[11px] text-amber-300/90 mt-1">▸ {t.why}</p>
                  </div>
                </div>
              ))}
            </Panel>
          )}

          {today && (
            <Panel
              code="TODAY"
              title="今日采集速报"
              action={
                <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                  {today.date} 入库
                </span>
              }
              className={top && top.length > 0 ? 'xl:col-span-6' : 'xl:col-span-12'}
              bodyClassName="p-4 space-y-4"
            >
              <div className="grid grid-cols-1 sm:grid-cols-12 gap-4">
                <div className="sm:col-span-4 flex flex-col justify-between">
                  <div>
                    <p className="text-3xl font-mono font-semibold text-sky-400 tabular-nums">
                      {today.total}
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">今日新增情报（条）</p>
                  </div>
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {Object.entries(today.by_type).map(([t, c]) => (
                      <span
                        key={t}
                        className="px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-[10px] font-mono text-slate-300 tabular-nums"
                      >
                        {t} <span className="text-sky-300">{c}</span>
                      </span>
                    ))}
                  </div>
                </div>

                <div className="sm:col-span-8 space-y-1.5">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                    采集来源 Top {today.by_source.length}
                  </p>
                  {today.by_source.slice(0, 7).map((s) => (
                    <div key={s.source} className="flex items-center gap-2">
                      <span
                        className="w-28 shrink-0 truncate text-[11px] text-slate-300"
                        title={s.source}
                      >
                        {s.source}
                      </span>
                      <div className="h-1.5 flex-1 rounded-full bg-white/[0.06] overflow-hidden">
                        <div
                          className="h-full rounded-full bg-sky-400/80 anim-bar"
                          style={{ width: `${(s.count / todayMax) * 100}%` }}
                        />
                      </div>
                      <span className="w-7 shrink-0 text-right text-[11px] font-mono text-white tabular-nums">
                        {s.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {today.recent_days.length > 0 && (
                <div className="pt-3 border-t border-white/[0.06]">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-2">
                    近 7 天入库对比
                  </p>
                  <div className="flex items-end gap-2 h-14">
                    {today.recent_days.map((m, i) => {
                      const isLatest = i === today.recent_days.length - 1;
                      return (
                        <div
                          key={m.day}
                          className="flex-1 flex flex-col items-center justify-end h-full"
                        >
                          <span className="text-[9px] font-mono text-slate-400 tabular-nums mb-0.5">
                            {m.count}
                          </span>
                          <div
                            className={`w-full rounded-t-sm ${
                              isLatest ? 'bg-sky-400' : 'bg-sky-400/30'
                            }`}
                            style={{ height: `${Math.max((m.count / recMax) * 100, 4)}%` }}
                          />
                          <span
                            className={`text-[9px] font-mono mt-1 tabular-nums ${
                              isLatest ? 'text-sky-300' : 'text-slate-500'
                            }`}
                          >
                            {m.day.slice(5)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </Panel>
          )}
        </div>
      ) : null}

      {/* Row 3: Vulnerability Category & Severity Drilldown + Donut */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {attackEntries.length > 0 && (
          <Panel
            code="CATEGORY"
            title="漏洞类别与严重度下钻"
            action={
              <div className="flex flex-wrap items-center gap-1 text-[10px] font-mono">
                <span className="px-1.5 py-0.5 rounded bg-rose-500/15 border border-rose-500/40 text-rose-300 tabular-nums">
                  KEV {dist?.kev ?? 0}
                </span>
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => {
                  const meta = getSeverityMeta(s);
                  const active = sel?.severity === s;
                  return (
                    <button
                      key={s}
                      onClick={() => drill({ severity: s, attack: undefined })}
                      className={`px-1.5 py-0.5 rounded border transition-colors tabular-nums ${
                        active
                          ? 'bg-sky-500/15 border-sky-400 text-sky-300'
                          : 'bg-white/[0.03] border-white/[0.08] text-slate-300 hover:border-white/[0.2]'
                      }`}
                    >
                      <span
                        className="inline-block w-1.5 h-1.5 rounded-full mr-1"
                        style={{ backgroundColor: meta.color }}
                      />
                      {s} {dist?.severity?.[s] ?? 0}
                    </button>
                  );
                })}
              </div>
            }
            className="xl:col-span-7"
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2">
              {attackEntries.map(([label, value], i) => {
                const active = sel?.attack === label;
                return (
                  <button
                    key={label}
                    type="button"
                    onClick={() => drill({ attack: label, severity: undefined })}
                    className={`flex items-center gap-2.5 rounded-lg px-2 py-1 text-left transition-colors ${
                      active ? 'bg-sky-500/15' : 'hover:bg-white/[0.04]'
                    }`}
                  >
                    <span
                      className={`w-24 shrink-0 truncate text-xs ${
                        active ? 'text-sky-300 font-medium' : 'text-slate-300'
                      }`}
                    >
                      {label}
                    </span>
                    <div className="h-2 flex-1 rounded-full bg-white/[0.06] overflow-hidden">
                      <div
                        className="h-full rounded-full anim-bar"
                        style={{
                          width: `${(value / attackMax) * 100}%`,
                          backgroundColor: CAT_COLORS[i % CAT_COLORS.length],
                        }}
                      />
                    </div>
                    <span className="w-9 shrink-0 text-right text-xs font-mono text-white tabular-nums">
                      {value}
                    </span>
                  </button>
                );
              })}
            </div>
          </Panel>
        )}

        <Panel
          code="DISTRIBUTION"
          title="知识库域分布"
          action={
            stats.sqlite.latest_date ? (
              <span className="text-[11px] font-mono text-slate-400 tabular-nums">
                最新 <span className="text-sky-300">{stats.sqlite.latest_date}</span>
              </span>
            ) : undefined
          }
          className={attackEntries.length > 0 ? 'xl:col-span-5' : 'xl:col-span-12'}
        >
          <DonutChart data={domainData} />
        </Panel>
      </div>

      {/* Drilldown Results with One-Click AI Investigation */}
      {sel && (
        <Panel
          code="DRILLDOWN"
          title={`${sel.severity ? `严重度 ${sel.severity}` : ''}${
            sel.severity && sel.attack ? ' × ' : ''
          }${sel.attack ? `攻击类型 ${sel.attack}` : ''}${vlist ? `（共 ${vlist.total} 条）` : ''}`}
          action={
            <Button variant="ghost" size="xs" onClick={() => drill(null)}>
              <X size={13} />
              关闭下钻
            </Button>
          }
          bodyClassName="p-3.5"
        >
          {vloading ? (
            <div className="flex items-center justify-center h-24">
              <span className="soc-dots">
                <span />
                <span />
                <span />
              </span>
            </div>
          ) : (vlist?.vulns.length ?? 0) === 0 ? (
            <p className="text-xs text-slate-400 text-center py-6">
              该过滤条件下暂无富化漏洞记录
            </p>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {vlist!.vulns.map((v) => (
                <div
                  key={v.cve_id}
                  className="p-3 rounded-xl bg-white/[0.025] border border-white/[0.07] hover:border-white/[0.15] transition-colors"
                >
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <a
                      href={v.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sky-300 font-semibold hover:underline inline-flex items-center gap-1"
                    >
                      {v.cve_id}
                      <ExternalLink size={10} />
                    </a>
                    {v.severity && <SeverityBadge severity={v.severity} />}
                    <span className="text-slate-300 tabular-nums">CVSS {v.cvss ?? '-'}</span>
                    {v.kev && <KevBadge />}
                    {v.attack_type && (
                      <span className="px-1.5 py-0.5 rounded bg-white/[0.05] border border-white/[0.08] text-[10px] text-slate-300">
                        {v.attack_type}
                      </span>
                    )}
                    <span className="ml-auto text-[11px] text-slate-500 tabular-nums">
                      {v.publish_time}
                    </span>
                    {onInvestigate && (
                      <button
                        onClick={() => onInvestigate(v.cve_id)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-sky-500/15 hover:bg-sky-400 hover:text-slate-950 border border-sky-400/35 text-sky-300 text-[10px] font-sans font-medium transition-colors"
                      >
                        <Sparkles size={10} />
                        AI 研判
                      </button>
                    )}
                  </div>
                  {v.summary_zh && (
                    <p className="text-xs text-slate-300 mt-1.5 leading-relaxed line-clamp-2">
                      {v.summary_zh}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>
      )}

      {/* Row 4: 30-Day Timeline */}
      {(dist?.days?.length ?? 0) > 0 && (
        <Panel code="TIMELINE" title="近 30 天每日情报收录趋势">
          <div className="flex items-end gap-1 h-28 pt-4">
            {dist!.days.map((m, i) => (
              <div
                key={m.day}
                className="group relative flex-1 flex flex-col justify-end items-center h-full"
              >
                <span className="pointer-events-none absolute -top-4 px-1.5 py-0.5 rounded bg-[#141b29] border border-white/[0.12] text-[10px] font-mono text-sky-300 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10 tabular-nums">
                  {m.day.slice(5)} · {m.count}
                </span>
                <div
                  className="w-full rounded-t-sm bg-sky-400/55 group-hover:bg-sky-400 transition-colors"
                  style={{ height: `${Math.max((m.count / dayMax) * 100, 3)}%` }}
                />
                <span className="text-[9px] font-mono text-slate-500 mt-1 tabular-nums">
                  {i % 5 === 0 ? m.day.slice(5) : ''}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Row 5: Platform Sources + Enrichment & Benchmark */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        {(dist?.article_sources?.length ?? 0) > 0 && (
          <Panel code="SOURCES" title="采集平台分布" className="xl:col-span-7">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-2">
                  文章 / 资讯平台 (Top {dist!.article_sources.length})
                </p>
                <div className="space-y-1.5">
                  {dist!.article_sources.map((s) => (
                    <div key={s.source} className="flex items-center gap-2">
                      <span
                        className="w-28 shrink-0 truncate text-xs text-slate-300"
                        title={s.source}
                      >
                        {s.source}
                      </span>
                      <div className="h-1.5 flex-1 rounded-full bg-white/[0.06] overflow-hidden">
                        <div
                          className="h-full rounded-full bg-sky-400 anim-bar"
                          style={{ width: `${(s.count / artMax) * 100}%` }}
                        />
                      </div>
                      <span className="w-9 shrink-0 text-right text-xs font-mono text-white tabular-nums">
                        {s.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-2">
                  学术论文平台
                </p>
                <div className="space-y-1.5">
                  {dist!.paper_sources.map((s) => (
                    <div key={s.source} className="flex items-center gap-2">
                      <span
                        className="w-28 shrink-0 truncate text-xs text-slate-300"
                        title={s.source}
                      >
                        {s.source}
                      </span>
                      <div className="h-1.5 flex-1 rounded-full bg-white/[0.06] overflow-hidden">
                        <div
                          className="h-full rounded-full bg-violet-400 anim-bar"
                          style={{ width: `${(s.count / papMax) * 100}%` }}
                        />
                      </div>
                      <span className="w-9 shrink-0 text-right text-xs font-mono text-white tabular-nums">
                        {s.count}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Panel>
        )}

        <div
          className={`space-y-4 ${
            (dist?.article_sources?.length ?? 0) > 0 ? 'xl:col-span-5' : 'xl:col-span-12'
          }`}
        >
          <Panel code="ENRICHMENT" title="情报富化与缝合指标">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
              {[
                { value: `${(stats.sqlite.cve_enrich_rate * 100).toFixed(1)}%`, label: 'CVE 富化率' },
                { value: `${(stats.sqlite.article_enrich_rate * 100).toFixed(1)}%`, label: '文章富化率' },
                { value: stats.sqlite.article_cve.toLocaleString(), label: '文章↔CVE 关联' },
                { value: stats.sqlite.paper_link.toLocaleString(), label: '论文↔组件关联' },
                { value: stats.sqlite.affected_component.toLocaleString(), label: '组件定位' },
                { value: stats.sqlite.cpes.toLocaleString(), label: 'CPE 资产覆盖' },
              ].map((it) => (
                <div
                  key={it.label}
                  className="rounded-lg bg-white/[0.025] border border-white/[0.06] px-3 py-2"
                >
                  <p className="text-base font-mono font-semibold text-sky-300 tabular-nums">
                    {it.value}
                  </p>
                  <p className="text-[11px] text-slate-400 mt-0.5">{it.label}</p>
                </div>
              ))}
            </div>
          </Panel>

          <Panel code="BENCHMARK" title="检索验证基准">
            <div className="grid grid-cols-2 gap-2.5">
              <div className="rounded-lg bg-emerald-500/[0.06] border border-emerald-400/25 px-3 py-2.5">
                <p className="text-[11px] text-slate-400">检索冒烟</p>
                <p className="text-lg font-mono font-semibold text-emerald-400 mt-0.5 tabular-nums">
                  {stats.bench.smoke}
                </p>
              </div>
              <div className="rounded-lg bg-emerald-500/[0.06] border border-emerald-400/25 px-3 py-2.5">
                <p className="text-[11px] text-slate-400">大规模基准</p>
                <p className="text-lg font-mono font-semibold text-emerald-400 mt-0.5 tabular-nums">
                  {stats.bench.large}
                </p>
              </div>
            </div>
          </Panel>
        </div>
      </div>

      {/* Row 6: Compact Pipeline */}
      <Panel code="PIPELINE" title="数据加工流水线">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
          {[
            {
              step: '01',
              code: 'MONITOR',
              label: '多源监测',
              desc: `${stats.collectors.count} 采集器 · ${stats.collectors.rss_sources} RSS`,
            },
            {
              step: '02',
              code: 'ENRICH',
              label: '三级富化',
              desc: 'AI 相关性判定 · 五层提取',
            },
            {
              step: '03',
              code: 'VECTOR',
              label: '向量索引',
              desc: `${stats.vector.count.toLocaleString()} 块 · ${stats.vector.dim} 维`,
            },
            {
              step: '04',
              code: 'QA AGENT',
              label: '智能问答',
              desc: '六路路由 · 缝合增强 · 防幻觉',
            },
          ].map((node, idx) => (
            <div
              key={node.code}
              className="rounded-xl bg-white/[0.025] border border-white/[0.07] px-3.5 py-2.5 flex items-center justify-between gap-2"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span className="text-[10px] font-mono text-sky-400">{node.step}</span>
                  <span className="text-[10px] font-mono text-slate-500">{node.code}</span>
                </div>
                <p className="text-xs font-semibold text-white">{node.label}</p>
                <p className="text-[11px] font-mono text-slate-400 truncate mt-0.5">{node.desc}</p>
              </div>
              {idx < 3 && (
                <ArrowRight size={14} className="hidden sm:block text-white/20 flex-shrink-0" />
              )}
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

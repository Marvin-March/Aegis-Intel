import React, { useEffect, useState } from 'react';
import { RefreshCw, X } from 'lucide-react';
import { getStats, getVulns, isMockMode } from '../api/client';
import type { StatsResponse, VulnListResponse } from '../types/contract';
import HeroNumber from './HeroNumber';
import DonutChart from './DonutChart';

export default function StatsTab() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // 下钻（2026-10-16）：严重度 chip / 攻击类别条点击 → 漏洞清单
  const [sel, setSel] = useState<{ severity?: string; attack?: string } | null>(null);
  const [vlist, setVlist] = useState<VulnListResponse | null>(null);
  const [vloading, setVloading] = useState(false);

  const drill = (next: { severity?: string; attack?: string } | null) => {
    setSel((cur) => {
      const same = cur && cur.severity === next?.severity && cur.attack === next?.attack;
      const target = same ? null : next;          // 点同一个 = 取消过滤
      setVlist(null);
      if (target) {
        setVloading(true);
        getVulns(target).then(setVlist).catch(() => setVlist(null))
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
        <span className="soc-dots"><span /><span /><span /></span>
      </div>
    );
  }

  if (error || !stats) {
    // 真实模式下降级：api.py 暂未提供 /api/stats（裁决 b），mock 模式照常演示
    const degraded = !isMockMode();
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-4">
        <p className={`text-center leading-relaxed ${degraded ? 'text-amber-400 max-w-xl' : 'text-soc-text-secondary'}`}>
          {degraded
            ? '数据看板依赖的 /api/stats 端点后端暂未提供（api.py 当前为 /ask /search /health /related 四端点）。此页当前仅在 mock 模式下演示完整看板。'
            : error || '加载失败'}
        </p>
        <button
          onClick={fetchStats}
          className="px-4 py-2 bg-soc-primary hover:bg-cyan-300 text-soc-bg font-medium rounded-lg transition-colors flex items-center gap-2"
        >
          <RefreshCw size={16} />
          重试
        </button>
      </div>
    );
  }

  const domainData = [
    { label: 'CVE 漏洞', value: stats.vector.domains.cve, color: '#f87171' },
    { label: '文章', value: stats.vector.domains.article, color: '#38bdf8' },
    { label: '论文', value: stats.vector.domains.paper, color: '#a78bfa' },
  ];

  // 看板二期：类别/时间/平台分布（dist 缺字段时优雅降级为空面板）
  // 类别全量展示（用户要求"越多越好"），"其他"强制沉底
  const dist = (stats as StatsResponse & { dist?: StatsResponse['dist'] }).dist;
  const attackEntries = Object.entries(dist?.attack ?? {})
    .sort((x, y) => (x[0] === '其他' ? 1 : 0) - (y[0] === '其他' ? 1 : 0) || y[1] - x[1]);
  const attackMax = Math.max(...attackEntries.map(([, v]) => v), 1);
  const dayMax = Math.max(...(dist?.days ?? []).map((m) => m.count), 1);
  const artMax = Math.max(...(dist?.article_sources ?? []).map((s) => s.count), 1);
  const papMax = Math.max(...(dist?.paper_sources ?? []).map((s) => s.count), 1);
  // 今日采集速报（2026-10-16）：crawl_time 入库口径
  const today = (stats as StatsResponse & { today?: StatsResponse['today'] }).today;
  const top = (stats as StatsResponse & { top_threats?: StatsResponse['top_threats'] }).top_threats;
  const todayMax = Math.max(...(today?.by_source ?? []).map((s) => s.count), 1);
  const recMax = Math.max(...(today?.recent_days ?? []).map((m) => m.count), 1);
  const CAT_COLORS = ['#f87171', '#38bdf8', '#a78bfa', '#34d399', '#fbbf24', '#f472b6', '#60a5fa', '#fb923c'];

  return (
    <div className="space-y-6">
      {/* Hero Numbers */}
      <div className="grid grid-cols-3 gap-4 animate-panel-reveal">
        <HeroNumber label="向量块总数" value={stats.vector.count} delay={0} />
        <HeroNumber label="情报记录数" value={stats.sqlite.records} delay={80} />
        <HeroNumber label="AI 相关漏洞" value={stats.sqlite.ai_vulns} delay={160} />
        <HeroNumber label="RSS 源数量" value={stats.collectors.rss_sources} delay={240} />
        <HeroNumber label="采集器数量" value={stats.collectors.count} delay={320} />
        <HeroNumber label="近 7 天新增情报" value={stats.sqlite.near7d} delay={400} />
      </div>

      {/* 今日采集速报（2026-10-16）：按入库时间口径，展示今天各源抓了多少 */}
      {today && (
        <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '60ms' }}>
          <div className="flex items-center justify-between mb-5">
            <div className="soc-eyebrow">TODAY · 今日采集速报</div>
            <p className="text-xs font-mono text-soc-text-muted">{today.date} 入库</p>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div>
              <p className="text-4xl font-mono text-soc-primary">{today.total}</p>
              <p className="text-[11px] text-soc-text-muted mt-1 tracking-wide">今日新增情报（条）</p>
              <div className="flex flex-wrap gap-1.5 mt-3">
                {Object.entries(today.by_type).map(([t, c]) => (
                  <span key={t} className="px-2 py-0.5 rounded border border-soc-border text-[11px] font-mono text-soc-text-secondary">
                    {t} <span className="text-soc-primary">{c}</span>
                  </span>
                ))}
              </div>
            </div>
            <div className="xl:col-span-2">
              <p className="text-xs text-soc-text-muted mb-2.5">按采集来源 Top 10</p>
              <div className="space-y-1.5">
                {today.by_source.map((s) => (
                  <div key={s.source} className="flex items-center gap-2">
                    <p className="w-36 shrink-0 truncate text-xs text-soc-text-secondary" title={s.source}>{s.source}</p>
                    <div className="h-2 flex-1 rounded-sm bg-soc-bg overflow-hidden">
                      <div className="h-full rounded-sm bg-soc-primary/70" style={{ width: `${(s.count / todayMax) * 100}%` }} />
                    </div>
                    <p className="w-8 shrink-0 text-right text-xs font-mono text-soc-text-primary">{s.count}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-5 pt-4 border-t border-soc-border">
            <p className="text-xs text-soc-text-muted mb-2">近 7 天入库对比</p>
            <div className="flex items-end gap-2 h-16">
              {today.recent_days.map((m, i) => (
                <div key={m.day} className="flex-1 flex flex-col items-center justify-end h-full">
                  <p className="text-[10px] font-mono text-soc-text-muted mb-0.5">{m.count}</p>
                  <div className={`w-full rounded-t-sm transition-colors ${i === today!.recent_days.length - 1 ? 'bg-soc-primary' : 'bg-soc-primary/35'}`}
                       style={{ height: `${Math.max((m.count / recMax) * 100, 2)}%` }} />
                  <p className={`text-[9px] font-mono mt-1 ${i === today!.recent_days.length - 1 ? 'text-soc-primary' : 'text-soc-text-muted'}`}>
                    {m.day.slice(5)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Domain Distribution */}
      <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '120ms' }}>
        <div className="flex items-center justify-between mb-6">
          <div className="soc-eyebrow">DISTRIBUTION · 域分布</div>
          {stats.sqlite.latest_date && (
            <p className="text-xs font-mono text-soc-text-muted">
              库内最新情报：<span className="text-soc-primary">{stats.sqlite.latest_date}</span>
            </p>
          )}
        </div>
        <DonutChart data={domainData} />
      </div>

      {/* Benchmark */}
      <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '200ms' }}>
        <div className="soc-eyebrow mb-4">BENCHMARK · 检索验证成绩</div>
        <div className="grid grid-cols-2 gap-4">
          {[
            { label: '检索冒烟', value: stats.bench.smoke },
            { label: '大规模基准', value: stats.bench.large },
          ].map((b) => (
            <div key={b.label} className="p-4 bg-soc-bg border border-soc-success/30 soc-lift">
              <p className="text-xs text-soc-text-muted mb-1 tracking-wider">{b.label}</p>
              <p className="text-xl text-soc-success font-mono">{b.value}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Category */}
      {attackEntries.length > 0 && (
        <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '240ms' }}>
          <div className="flex flex-wrap items-center justify-between gap-2 mb-5">
            <div className="soc-eyebrow">CATEGORY · 漏洞类别占比（富化攻击类型）</div>
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
              <span className="px-2 py-0.5 rounded border border-soc-danger/50 text-soc-danger">
                KEV 在野 {dist?.kev ?? 0}
              </span>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => (
                <button key={s}
                        onClick={() => drill({ severity: s, attack: undefined })}
                        title={`查看 ${s} 漏洞清单`}
                        className={`px-2 py-0.5 rounded border transition-colors cursor-pointer ${
                          sel?.severity === s
                            ? 'border-soc-primary bg-soc-primary/10 text-soc-primary'
                            : 'border-soc-border text-soc-text-secondary hover:border-soc-primary/60 hover:text-soc-text-primary'
                        }`}>
                  {s} {dist?.severity?.[s] ?? 0}
                </button>
              ))}
            </div>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-x-8 gap-y-2.5">
            {attackEntries.map(([label, value], i) => (
              <div key={label}
                   onClick={() => drill({ attack: label, severity: undefined })}
                   title={`查看「${label}」漏洞清单`}
                   className={`flex items-center gap-3 rounded px-1 py-0.5 cursor-pointer transition-colors ${
                     sel?.attack === label ? 'bg-soc-primary/10' : 'hover:bg-soc-bg'
                   }`}>
                <p className={`w-28 shrink-0 truncate text-xs ${
                  sel?.attack === label ? 'text-soc-primary' : 'text-soc-text-secondary'
                }`}>{label}</p>
                <div className="h-2.5 flex-1 rounded-sm bg-soc-bg overflow-hidden">
                  <div className="h-full rounded-sm"
                       style={{ width: `${(value / attackMax) * 100}%`, background: CAT_COLORS[i % CAT_COLORS.length] }} />
                </div>
                <p className="w-12 shrink-0 text-right text-xs font-mono text-soc-text-primary">{value}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 下钻结果：severity/attack 点击后的漏洞清单 */}
      {sel && (
        <div className="soc-glass p-6 animate-panel-reveal">
          <div className="flex items-center justify-between mb-4">
            <div className="soc-eyebrow">
              DRILLDOWN · {sel.severity ? `严重度 ${sel.severity}` : ''}
              {sel.severity && sel.attack ? ' × ' : ''}
              {sel.attack ? `类别 ${sel.attack}` : ''}
              {vlist ? ` · 共 ${vlist.total} 条` : ''}
            </div>
            <button onClick={() => drill(null)}
                    className="flex items-center gap-1 text-xs text-soc-text-muted hover:text-soc-text-primary transition-colors">
              <X size={14} /> 关闭
            </button>
          </div>
          {vloading ? (
            <div className="flex items-center justify-center h-24">
              <span className="soc-dots"><span /><span /><span /></span>
            </div>
          ) : (vlist?.vulns.length ?? 0) === 0 ? (
            <p className="text-sm text-soc-text-muted text-center py-8">该过滤条件下暂无富化漏洞记录</p>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {vlist!.vulns.map((v) => (
                <a key={v.cve_id} href={v.url} target="_blank" rel="noreferrer"
                   className="block p-3 rounded-lg bg-soc-bg border border-soc-border hover:border-soc-primary/60 transition-colors">
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className="text-soc-primary">{v.cve_id}</span>
                    <span className="text-soc-text-muted">CVSS {v.cvss ?? '-'}</span>
                    {v.kev && <span className="px-1.5 rounded border border-soc-danger/60 text-soc-danger">KEV</span>}
                    {v.attack_type && <span className="px-1.5 rounded border border-soc-border text-soc-text-muted">{v.attack_type}</span>}
                    <span className="ml-auto text-soc-text-muted">{v.publish_time}</span>
                  </div>
                  {v.summary_zh && <p className="text-xs text-soc-text-secondary mt-1.5 leading-relaxed">{v.summary_zh}</p>}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Timeline */}
      {(dist?.days?.length ?? 0) > 0 && (
        <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '260ms' }}>
          <div className="soc-eyebrow mb-5">TIMELINE · 近 30 天每日情报收录</div>
          <div className="flex items-end gap-1 h-32">
            {dist!.days.map((m, i) => (
              <div key={m.day} className="group relative flex-1 flex flex-col justify-end items-center h-full">
                <p className="absolute -top-1 text-[10px] font-mono text-soc-primary opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                  {m.day.slice(5)} · {m.count}
                </p>
                <div className="w-full rounded-t-sm bg-soc-primary/60 group-hover:bg-soc-primary transition-colors"
                     style={{ height: `${Math.max((m.count / dayMax) * 100, 2)}%` }} />
                <p className="text-[9px] font-mono text-soc-text-muted mt-1">
                  {i % 5 === 0 ? m.day.slice(5) : ''}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sources */}
      {(dist?.article_sources?.length ?? 0) > 0 && (
        <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '280ms' }}>
          <div className="soc-eyebrow mb-5">SOURCES · 采集平台分布</div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div>
              <p className="text-xs text-soc-text-muted mb-2.5">文章 / 资讯平台（Top {dist!.article_sources.length}）</p>
              <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 xl:grid-cols-2">
                {dist!.article_sources.map((s) => (
                  <div key={s.source} className="flex items-center gap-2">
                    <p className="w-28 shrink-0 truncate text-xs text-soc-text-secondary">{s.source}</p>
                    <div className="h-2 flex-1 rounded-sm bg-soc-bg overflow-hidden">
                      <div className="h-full rounded-sm" style={{ width: `${(s.count / artMax) * 100}%`, background: '#38bdf8' }} />
                    </div>
                    <p className="w-10 shrink-0 text-right text-xs font-mono text-soc-text-primary">{s.count}</p>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <p className="text-xs text-soc-text-muted mb-2.5">论文平台</p>
              <div className="space-y-1.5">
                {dist!.paper_sources.map((s) => (
                  <div key={s.source} className="flex items-center gap-2">
                    <p className="w-28 shrink-0 truncate text-xs text-soc-text-secondary">{s.source}</p>
                    <div className="h-2 flex-1 rounded-sm bg-soc-bg overflow-hidden">
                      <div className="h-full rounded-sm" style={{ width: `${(s.count / papMax) * 100}%`, background: '#a78bfa' }} />
                    </div>
                    <p className="w-10 shrink-0 text-right text-xs font-mono text-soc-text-primary">{s.count}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Enrichment */}
      <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '280ms' }}>
        <div className="soc-eyebrow mb-4">ENRICHMENT · 富化数字</div>
        <div className="grid grid-cols-3 xl:grid-cols-6 gap-4">
          {[
            { value: `${(stats.sqlite.cve_enrich_rate * 100).toFixed(1)}%`, label: 'CVE 富化率' },
            { value: `${(stats.sqlite.article_enrich_rate * 100).toFixed(1)}%`, label: '文章富化率' },
            { value: String(stats.sqlite.article_cve), label: '文章↔CVE 关联' },
            { value: String(stats.sqlite.paper_link), label: '论文↔组件关联' },
            { value: String(stats.sqlite.affected_component), label: '组件定位' },
            { value: String(stats.sqlite.cpes), label: 'CPE 资产覆盖' },
          ].map((it, i) => (
            <div key={it.label} className="animate-fade-slide-in" style={{ animationDelay: `${340 + i * 60}ms` }}>
              <p className="text-xl font-mono text-soc-primary">{it.value}</p>
              <p className="text-[11px] text-soc-text-muted mt-1 tracking-wide">{it.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* 今日重点关注 Top3（应急决策，2026-10-16） */}
      {top && top.length > 0 ? (
        <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '320ms' }}>
          <div className="flex items-center justify-between mb-5">
            <div className="soc-eyebrow">PRIORITY · 今日重点关注 TOP 3</div>
            <p className="text-xs font-mono text-soc-text-muted">按 KEV 在野 / CVSS / EPSS 加权排序</p>
          </div>
          <div className="space-y-3">
            {top.map((t, i) => (
              <div key={t.cve_id}
                   className="flex items-start gap-3 p-3 bg-soc-bg border border-soc-border hover:border-soc-primary/60 transition-colors rounded-lg">
                <div className={`w-9 h-9 flex-shrink-0 flex items-center justify-center font-mono text-sm border rounded ${
                  t.kev ? 'border-soc-danger/60 text-soc-danger' : 'border-soc-primary/60 text-soc-primary'
                }`}>
                  {i + 1}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className="text-soc-primary font-semibold">{t.cve_id}</span>
                    <span className="text-soc-text-muted">CVSS {t.cvss ?? '-'}</span>
                    {t.kev && <span className="px-1.5 rounded border border-soc-danger/60 text-soc-danger">KEV 在野</span>}
                    <span className="text-soc-text-muted">EPSS {t.epss.toFixed(3)}</span>
                  </div>
                  <p className="text-xs text-soc-text-secondary mt-1.5 leading-relaxed line-clamp-2" title={t.summary}>
                    {t.summary}
                  </p>
                  <p className="text-[11px] text-soc-warning mt-1.5">▸ {t.why}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* Pipeline Diagram */}
      <div className="soc-glass p-6 animate-panel-reveal" style={{ animationDelay: '360ms' }}>
        <div className="soc-eyebrow mb-8">PIPELINE · 流水线</div>
        <div className="flex items-center justify-between">
          {[
            {
              label: '监测',
              code: 'MONITOR',
              desc: `${stats.collectors.count} 采集器 · ${stats.collectors.rss_sources} RSS`,
            },
            { label: '富化', code: 'ENRICH', desc: '三级裁决 · 五层管线' },
            {
              label: '向量化',
              code: 'VECTOR',
              desc: `${stats.vector.count.toLocaleString()} 块 · ${stats.vector.dim} 维`,
            },
            { label: '问答', code: 'QA', desc: '路由 · 检索 · 生成' },
          ].map((node, idx) => (
            <React.Fragment key={idx}>
              <div
                className="flex-1 text-center animate-fade-slide-in"
                style={{ animationDelay: `${420 + idx * 120}ms` }}
              >
                {/* 切角菱形节点 */}
                <div className="relative w-14 h-14 mx-auto mb-3">
                  <div className="absolute inset-0 border border-soc-primary/60 rotate-45 transition-transform duration-500 hover:rotate-90" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="font-mono text-soc-primary text-sm">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                  </div>
                </div>
                <p className="text-[10px] font-mono tracking-[0.24em] text-soc-text-muted mb-1">
                  {node.code}
                </p>
                <p className="text-sm text-soc-text-primary mb-1 tracking-[0.14em]">{node.label}</p>
                <p className="text-[11px] text-soc-text-muted font-mono">{node.desc}</p>
              </div>
              {idx < 3 && (
                <div className="w-16 flex-shrink-0 flex items-center">
                  <div className="flex-1 h-px bg-soc-border" />
                  <div className="w-1.5 h-1.5 rotate-45 bg-soc-primary/50 -ml-1" />
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

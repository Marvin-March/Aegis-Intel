import { useEffect, useState } from 'react';
import { RefreshCw, Play, CheckCircle2, XCircle, Loader2, Clock } from 'lucide-react';
import { getRuns, triggerCollect, isMockMode } from '../api/client';
import type { RunRecord } from '../types/contract';
import Modal from './Modal';
import { toast } from './Toast';
import { Panel } from './ui/Panel';
import { Button } from './ui/Button';

type ModeFilter = 'all' | 'daily' | 'manual' | 'backfill';

export default function MonitorTab() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [modeFilter, setModeFilter] = useState<ModeFilter>('all');

  const fetchRuns = async () => {
    try {
      const data = await getRuns();
      setRuns(data.runs);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchRuns, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleTrigger = () => setConfirmOpen(true);

  const doTrigger = async () => {
    setConfirmOpen(false);
    setTriggering(true);
    try {
      const result = await triggerCollect({ mode: 'manual' });
      toast.success(`采集任务已启动：${result.run_id}`);
      fetchRuns();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : '触发失败');
    } finally {
      setTriggering(false);
    }
  };

  const modeBadge: Record<RunRecord['mode'], string> = {
    daily: 'bg-sky-500/15 border-sky-500/35 text-sky-300',
    manual: 'bg-violet-500/15 border-violet-500/35 text-violet-300',
    backfill: 'bg-amber-500/15 border-amber-500/35 text-amber-300',
  };

  // 基于真实 runs 列表派生摘要统计（无虚假数据）
  const okCount = runs.filter((r) => r.status === 'ok').length;
  const failCount = runs.filter((r) => r.status === 'failed').length;
  const runningCount = runs.filter((r) => r.status === 'running').length;
  const totalNew = runs.reduce((acc, r) => acc + (r.new_records > 0 ? r.new_records : 0), 0);

  const filteredRuns =
    modeFilter === 'all' ? runs : runs.filter((r) => r.mode === modeFilter);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex items-center gap-2.5 text-xs font-mono text-soc-text-muted">
          <span className="soc-dots">
            <span />
            <span />
            <span />
          </span>
          LOADING COLLECTOR RUNS...
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[1440px] mx-auto space-y-4 animate-fade-in">
      {/* Top Action & Schedule Bar */}
      <div className="aegis-surface px-4 py-3 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <Clock size={15} className="text-soc-primary flex-shrink-0" />
          <div className="min-w-0">
            <p className="text-xs font-semibold text-soc-text-primary">
              多源情报采集调度与运行日志
            </p>
            <p className="text-[11px] text-soc-text-muted">
              定时策略：每日 06:05 采集 / 07:35 富化加工错峰执行 · 支持随时触发手动增量
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <label className="inline-flex items-center gap-1.5 text-xs text-soc-text-secondary cursor-pointer hover:text-soc-text-primary">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-cyan-400 rounded"
            />
            自动刷新 (10s)
          </label>
          <Button variant="secondary" size="sm" onClick={fetchRuns}>
            <RefreshCw size={13} />
            刷新
          </Button>
          <Button variant="primary" size="sm" onClick={handleTrigger} disabled={triggering}>
            {triggering ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <Play size={13} />
            )}
            立即采集
          </Button>
        </div>
      </div>

      {/* Real-Data Derived Summary Strip */}
      {runs.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <div className="aegis-surface px-3.5 py-2.5">
            <p className="text-[11px] text-soc-text-muted">列表运行记录</p>
            <p className="text-lg font-mono font-semibold text-soc-text-primary tabular-nums mt-0.5">
              {runs.length}
            </p>
          </div>
          <div className="aegis-surface px-3.5 py-2.5">
            <p className="text-[11px] text-soc-text-muted">成功 / 运行中</p>
            <p className="text-lg font-mono font-semibold text-emerald-400 tabular-nums mt-0.5">
              {okCount}
              {runningCount > 0 && (
                <span className="text-xs text-soc-primary ml-1.5">({runningCount} 运行中)</span>
              )}
            </p>
          </div>
          <div className="aegis-surface px-3.5 py-2.5">
            <p className="text-[11px] text-soc-text-muted">失败次数</p>
            <p
              className={`text-lg font-mono font-semibold tabular-nums mt-0.5 ${
                failCount > 0 ? 'text-red-400' : 'text-soc-text-secondary'
              }`}
            >
              {failCount}
            </p>
          </div>
          <div className="aegis-surface px-3.5 py-2.5">
            <p className="text-[11px] text-soc-text-muted">累计新增情报</p>
            <p className="text-lg font-mono font-semibold text-soc-primary tabular-nums mt-0.5">
              {totalNew.toLocaleString()}
            </p>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="rounded-md p-3.5 bg-amber-500/10 border border-amber-500/35 text-xs flex items-center justify-between gap-4">
          <span className="text-amber-300 leading-relaxed">
            {!isMockMode()
              ? '情报监测依赖的 /api/runs 端点后端暂未提供（api.py 当前为 /ask /search /health /related 四端点）。此页当前仅在 mock 模式下演示。'
              : error}
          </span>
          <Button variant="secondary" size="xs" onClick={fetchRuns}>
            重试
          </Button>
        </div>
      )}

      {/* Runs Data Table */}
      <Panel
        code="COLLECTOR RUNS"
        title="采集运行历史"
        action={
          <div className="flex items-center gap-1">
            {(['all', 'daily', 'manual', 'backfill'] as const).map((m) => (
              <button
                key={m}
                onClick={() => setModeFilter(m)}
                className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase border transition-colors ${
                  modeFilter === m
                    ? 'bg-soc-primary/15 border-soc-primary/40 text-soc-primary'
                    : 'border-soc-border text-soc-text-muted hover:text-soc-text-primary'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-soc-bg/80 border-b border-soc-border text-[10px] font-mono uppercase tracking-wider text-soc-text-muted">
                <th className="px-4 py-2.5">运行 ID</th>
                <th className="px-4 py-2.5">触发模式</th>
                <th className="px-4 py-2.5">开始时间</th>
                <th className="px-4 py-2.5 text-right">耗时</th>
                <th className="px-4 py-2.5 text-right">新增记录</th>
                <th className="px-4 py-2.5 text-right">状态</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border/70 text-xs">
              {filteredRuns.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-soc-text-muted">
                    暂无匹配的采集运行记录
                  </td>
                </tr>
              ) : (
                filteredRuns.map((run) => (
                  <tr
                    key={run.run_id}
                    className="hover:bg-soc-hover/50 transition-colors font-mono"
                  >
                    <td className="px-4 py-2.5 text-soc-text-primary">{run.run_id}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] uppercase ${
                          modeBadge[run.mode]
                        }`}
                      >
                        {run.mode}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-soc-text-secondary tabular-nums">
                      {run.started_at}
                    </td>
                    <td className="px-4 py-2.5 text-right text-soc-text-secondary tabular-nums">
                      {run.duration_s > 0 ? `${run.duration_s}s` : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right text-soc-text-primary tabular-nums">
                      {run.new_records > 0 ? `+${run.new_records}` : '—'}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {run.status === 'ok' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/35 text-emerald-400 text-[10px]">
                          <CheckCircle2 size={10} />
                          OK
                        </span>
                      ) : run.status === 'running' ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-soc-primary/15 border border-soc-primary/40 text-soc-primary text-[10px]">
                          <Loader2 size={10} className="animate-spin" />
                          RUNNING
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 border border-red-500/35 text-red-400 text-[10px]">
                          <XCircle size={10} />
                          FAILED
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Trigger Confirmation Modal */}
      <Modal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="确认触发手动增量采集？"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
              取消
            </Button>
            <Button variant="primary" onClick={doTrigger}>
              确认触发
            </Button>
          </>
        }
      >
        <p>
          即将以 <code className="px-1.5 py-0.5 rounded bg-soc-bg border border-soc-border font-mono text-soc-primary">manual</code>{' '}
          模式启动一次增量采集任务。
        </p>
        <p className="mt-2 text-soc-text-muted">
          采集耗时通常为数分钟，启动后可在运行历史表中实时观察状态流转（running → ok / failed）。
        </p>
      </Modal>
    </div>
  );
}

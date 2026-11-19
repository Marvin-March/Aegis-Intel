import { useEffect, useState } from 'react';
import { RefreshCw, Play } from 'lucide-react';
import { getRuns, triggerCollect, isMockMode } from '../api/client';
import type { RunRecord } from '../types/contract';
import Modal from './Modal';
import { toast } from './Toast';

export default function MonitorTab() {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [confirmOpen, setConfirmOpen] = useState(false);

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

  // K2：原生 confirm() 换成应用内 Modal
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

  const modeColors = {
    daily: 'border-blue-400/40 text-blue-300',
    manual: 'border-purple-400/40 text-purple-300',
    backfill: 'border-soc-warning/50 text-soc-warning',
  };

  const statusColors = {
    ok: 'border-soc-success/50 text-soc-success',
    running: 'border-soc-primary/60 text-soc-primary animate-pulse',
    failed: 'border-soc-danger/50 text-soc-danger',
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <span className="soc-dots"><span /><span /><span /></span>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-panel-reveal">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="soc-eyebrow mb-2">COLLECTOR RUNS · 采集运行历史</div>
          <p className="text-xs text-soc-text-muted tracking-wide">
            自动化：每日 06:05 采集 / 07:35 加工错峰定时 · 此页触发手动增量
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-soc-text-secondary cursor-pointer hover:text-soc-text-primary transition-colors">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-[#38bdf8]"
            />
            自动刷新 (10s)
          </label>
          <button
            onClick={fetchRuns}
            className="soc-btn-ghost px-3 py-2 text-xs tracking-[0.12em] flex items-center gap-2"
          >
            <RefreshCw size={14} />
            刷新
          </button>
          <button
            onClick={handleTrigger}
            disabled={triggering}
            className="soc-btn-primary px-4 py-2 text-sm font-medium tracking-[0.12em] disabled:opacity-50 flex items-center gap-2"
          >
            {triggering ? (
              <span className="soc-dots soc-dots-dark"><span /><span /><span /></span>
            ) : (
              <Play size={14} />
            )}
            立即采集
          </button>
        </div>
      </div>

      {/* Error（真实模式下降级：api.py 暂未提供 /api/runs，裁决 b） */}
      {error && (
        <div className="p-4 bg-soc-warning/10 border border-soc-warning/40 text-sm flex items-center justify-between gap-4">
          <span className="text-soc-warning">
            {!isMockMode()
              ? '情报监测依赖的 /api/runs 端点后端暂未提供（api.py 当前为 /ask /search /health /related 四端点）。此页当前仅在 mock 模式下演示。'
              : error}
          </span>
          <button
            onClick={fetchRuns}
            className="soc-btn-ghost px-3 py-1.5 text-xs flex-shrink-0"
          >
            重试
          </button>
        </div>
      )}

      {/* Runs Table */}
      <div className="soc-glass overflow-hidden">
        <table className="w-full">
          <thead className="bg-soc-bg border-b border-soc-border">
            <tr>
              {['运行 ID', '模式', '开始时间', '耗时', '新增记录', '状态'].map((h) => (
                <th
                  key={h}
                  className="px-4 py-3 text-left text-[10px] font-mono tracking-[0.2em] text-soc-text-muted"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map((run, i) => (
              <tr
                key={run.run_id}
                className="border-b border-soc-border hover:bg-soc-hover transition-colors animate-fade-slide-in"
                style={{ animationDelay: `${i * 40}ms` }}
              >
                <td className="px-4 py-3 text-sm font-mono text-soc-text-primary">{run.run_id}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 text-[10px] font-mono tracking-wider border ${modeColors[run.mode]}`}>
                    {run.mode.toUpperCase()}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-soc-text-secondary font-mono">
                  {run.started_at}
                </td>
                <td className="px-4 py-3 text-sm text-soc-text-secondary font-mono">
                  {run.duration_s > 0 ? `${run.duration_s}s` : '-'}
                </td>
                <td className="px-4 py-3 text-sm text-soc-text-secondary font-mono">
                  {run.new_records > 0 ? run.new_records : '-'}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 text-[10px] font-mono tracking-wider border ${statusColors[run.status]}`}>
                    {run.status === 'ok' ? '● OK' : run.status === 'running' ? '◐ RUN' : '▲ FAIL'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 采集确认（应用内 Modal，K2） */}
      <Modal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="确认触发手动采集？"
        footer={
          <>
            <button
              onClick={() => setConfirmOpen(false)}
              className="soc-btn-ghost px-4 py-2 text-sm"
            >
              取消
            </button>
            <button
              onClick={doTrigger}
              className="soc-btn-primary px-4 py-2 text-sm font-medium"
            >
              确认触发
            </button>
          </>
        }
      >
        <p>
          即将以 <span className="text-soc-text-primary font-mono">manual</span>{' '}
          模式启动一次增量采集任务。
        </p>
        <p className="mt-2">
          采集耗时通常为数分钟，任务启动后可在下方运行历史表中观察状态流转（running → ok/failed）。
        </p>
      </Modal>
    </div>
  );
}

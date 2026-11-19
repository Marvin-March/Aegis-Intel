import type {
  RunsResponse,
  RunRecord,
  CollectRequest,
  CollectResponse,
} from '../types/contract';

let mockRunsList: RunRecord[] = [
  {
    run_id: '20261009-0605',
    mode: 'daily',
    started_at: '2026-10-09 06:05:12',
    duration_s: 420,
    new_records: 128,
    status: 'ok',
  },
  {
    run_id: '20261008-0605',
    mode: 'daily',
    started_at: '2026-10-08 06:05:08',
    duration_s: 385,
    new_records: 95,
    status: 'ok',
  },
  {
    run_id: '20261007-1432',
    mode: 'manual',
    started_at: '2026-10-07 14:32:56',
    duration_s: 512,
    new_records: 167,
    status: 'ok',
  },
  {
    run_id: '20261007-0605',
    mode: 'daily',
    started_at: '2026-10-07 06:05:15',
    duration_s: 398,
    new_records: 103,
    status: 'ok',
  },
  {
    run_id: '20261006-0605',
    mode: 'daily',
    started_at: '2026-10-06 06:05:10',
    duration_s: 445,
    new_records: 142,
    status: 'ok',
  },
  {
    run_id: '20261005-1820',
    mode: 'backfill',
    started_at: '2026-10-05 18:20:33',
    duration_s: 1823,
    new_records: 456,
    status: 'ok',
  },
  {
    run_id: '20261005-0605',
    mode: 'daily',
    started_at: '2026-10-05 06:05:19',
    duration_s: 367,
    new_records: 88,
    status: 'ok',
  },
  {
    run_id: '20261004-0605',
    mode: 'daily',
    started_at: '2026-10-04 06:05:07',
    duration_s: 412,
    new_records: 115,
    status: 'ok',
  },
];

export function mockRuns(): RunsResponse {
  return { runs: mockRunsList };
}

export function mockCollect(request: CollectRequest): CollectResponse {
  const now = new Date();
  const runId = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}`;

  const newRun: RunRecord = {
    run_id: runId,
    mode: request.mode as 'manual',
    started_at: now.toISOString().replace('T', ' ').slice(0, 19),
    duration_s: 0,
    new_records: 0,
    status: 'running',
  };

  // 添加到列表头部
  mockRunsList.unshift(newRun);

  // 模拟状态变化：15 秒后变为 ok
  setTimeout(() => {
    const idx = mockRunsList.findIndex((r) => r.run_id === runId);
    if (idx !== -1) {
      mockRunsList[idx].status = 'ok';
      mockRunsList[idx].duration_s = 438;
      mockRunsList[idx].new_records = 152;
    }
  }, 15000);

  return { run_id: runId, started: true };
}

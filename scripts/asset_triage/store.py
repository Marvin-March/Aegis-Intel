# -*- coding: utf-8 -*-
"""资产暴露面研判——存储层。

复用主项目的 SQLite（data/index.sqlite）而不是另建库：漏洞情报本来就住在
vuln_meta / records 里，资产与工单放同一个库才能做一致性事务与联表查询。

新增表（全部 IF NOT EXISTS，不改动任何既有表结构）：
  asset_component     企业组件与版本清单
  advisory_range      公告的结构化版本区间（补 vuln_meta.affected_versions 只有文本的缺口）
  exposure_finding    资产 × 公告的匹配结论 + 证据指纹
  change_ticket       变更工单草稿与审批状态机
  ticket_event        工单状态流转审计日志
  asset_candidate     本机采集候选及当前审核状态
  asset_review_event  候选审核审计记录
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_component (
    asset_id       TEXT PRIMARY KEY,
    component      TEXT NOT NULL,
    ecosystem      TEXT NOT NULL,
    version        TEXT NOT NULL,
    owner          TEXT DEFAULT '',
    business_unit  TEXT DEFAULT '',
    environment    TEXT DEFAULT 'prod',
    criticality    TEXT DEFAULT 'medium',
    exposure       TEXT DEFAULT 'internal',
    app_name       TEXT DEFAULT '',
    source         TEXT DEFAULT 'manual',
    detected_at    TEXT DEFAULT '',
    evidence_json  TEXT DEFAULT '{}',
    updated_at     TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_asset_pkg ON asset_component(ecosystem, component);

CREATE TABLE IF NOT EXISTS asset_candidate (
    candidate_id      TEXT PRIMARY KEY,
    scope             TEXT NOT NULL,
    ecosystem         TEXT NOT NULL,
    component         TEXT NOT NULL,
    observations_json TEXT NOT NULL,
    revision          INTEGER NOT NULL DEFAULT 1,
    status            TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'confirmed', 'rejected')),
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_candidate_review ON asset_candidate(status, scope);

CREATE TABLE IF NOT EXISTS asset_review_event (
    id           INTEGER PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES asset_candidate(candidate_id),
    revision     INTEGER NOT NULL,
    action       TEXT NOT NULL,
    actor        TEXT NOT NULL,
    reason       TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisory_range (
    advisory_id     TEXT NOT NULL,
    cve_id          TEXT DEFAULT '',
    ecosystem       TEXT NOT NULL,
    package         TEXT NOT NULL,
    range_raw       TEXT NOT NULL,
    range_normalized TEXT DEFAULT '',
    first_patched   TEXT DEFAULT '',
    severity        TEXT DEFAULT 'unknown',
    cvss            REAL,
    kev             INTEGER DEFAULT 0,
    published_at    TEXT DEFAULT '',
    summary         TEXT DEFAULT '',
    url             TEXT DEFAULT '',
    source          TEXT DEFAULT '',
    fetched_at      TEXT DEFAULT '',
    PRIMARY KEY (advisory_id, ecosystem, package, range_raw)
);
CREATE INDEX IF NOT EXISTS idx_range_pkg ON advisory_range(ecosystem, package);

CREATE TABLE IF NOT EXISTS exposure_finding (
    finding_id       TEXT PRIMARY KEY,
    asset_id         TEXT NOT NULL,
    advisory_id      TEXT NOT NULL,
    cve_id           TEXT DEFAULT '',
    component        TEXT NOT NULL,
    ecosystem        TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    range_raw        TEXT NOT NULL,
    first_patched    TEXT DEFAULT '',
    severity         TEXT DEFAULT 'unknown',
    cvss             REAL,
    priority         TEXT DEFAULT 'P4',
    match_reason     TEXT DEFAULT '',
    evidence_hash    TEXT DEFAULT '',
    advisory_url     TEXT DEFAULT '',
    published_at     TEXT DEFAULT '',
    summary          TEXT DEFAULT '',
    status           TEXT DEFAULT 'open',
    run_id           TEXT DEFAULT '',
    created_at       TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_finding_asset ON exposure_finding(asset_id);

CREATE TABLE IF NOT EXISTS change_ticket (
    ticket_id       TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    app_name        TEXT DEFAULT '',
    owner           TEXT NOT NULL,
    priority        TEXT DEFAULT 'P3',
    status          TEXT DEFAULT 'draft',
    finding_ids     TEXT DEFAULT '[]',
    evidence_hash   TEXT DEFAULT '',
    evidence_json   TEXT DEFAULT '{}',
    impact          TEXT DEFAULT '',
    remediation     TEXT DEFAULT '',
    rollback        TEXT DEFAULT '',
    verification    TEXT DEFAULT '',
    approver        TEXT DEFAULT '',
    approve_comment TEXT DEFAULT '',
    created_at      TEXT DEFAULT '',
    updated_at      TEXT DEFAULT '',
    submitted_at    TEXT DEFAULT '',
    decided_at      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS ticket_event (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT DEFAULT '',
    role        TEXT DEFAULT '',
    comment     TEXT DEFAULT '',
    from_status TEXT DEFAULT '',
    to_status   TEXT DEFAULT '',
    created_at  TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_event_ticket ON ticket_event(ticket_id);
"""

# 审批状态机：只允许这些迁移，避免实现里到处写 if
ALLOWED_TRANSITIONS = {
    ("draft", "pending_approval"),
    ("pending_approval", "approved"),
    ("pending_approval", "rejected"),
    ("rejected", "draft"),
    ("approved", "closed"),
}


class TicketTransitionError(ValueError):
    pass


class Store:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.db
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    # ------------------------------------------------------------ 资产

    def upsert_assets(self, assets: list[dict[str, Any]], now: str, *,
                      connection: sqlite3.Connection | None = None) -> int:
        """写入资产。缺失的可选字段补默认值，避免一条脏数据拖垮整批导入。"""
        defaults = {
            "asset_id": "", "component": "", "ecosystem": "pypi", "version": "",
            "owner": "", "business_unit": "", "environment": "prod",
            "criticality": "medium", "exposure": "internal", "app_name": "",
            "source": "manual", "detected_at": "", "evidence_json": "{}",
        }
        sql = """INSERT INTO asset_component
            (asset_id, component, ecosystem, version, owner, business_unit,
             environment, criticality, exposure, app_name, source, detected_at,
             evidence_json, updated_at)
            VALUES (:asset_id,:component,:ecosystem,:version,:owner,:business_unit,
                    :environment,:criticality,:exposure,:app_name,:source,:detected_at,
                    :evidence_json,:updated_at)
            ON CONFLICT(asset_id) DO UPDATE SET
                component=excluded.component, ecosystem=excluded.ecosystem,
                version=excluded.version, owner=excluded.owner,
                business_unit=excluded.business_unit, environment=excluded.environment,
                criticality=excluded.criticality, exposure=excluded.exposure,
                app_name=excluded.app_name, source=excluded.source,
                detected_at=excluded.detected_at, evidence_json=excluded.evidence_json,
                updated_at=excluded.updated_at"""
        rows = []
        for a in assets:
            merged = {**defaults, **{k: v for k, v in a.items() if v is not None}}
            merged["updated_at"] = now
            rows.append(merged)
        if connection is None:
            with self.tx() as db:
                db.executemany(sql, rows)
        else:
            connection.executemany(sql, rows)
        return len(rows)

    def list_assets(self, *, confirmed_only: bool = False) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            """SELECT a.* FROM asset_component AS a
               LEFT JOIN asset_candidate AS c ON c.candidate_id=a.asset_id
               WHERE NOT ? OR c.candidate_id IS NULL OR c.status='confirmed'
               ORDER BY a.app_name, a.component, a.asset_id""", (confirmed_only,))]

    # ------------------------------------------------------------ 公告区间

    def upsert_advisories(self, rows: list[dict[str, Any]]) -> int:
        sql = """INSERT INTO advisory_range
            (advisory_id, cve_id, ecosystem, package, range_raw, range_normalized,
             first_patched, severity, cvss, kev, published_at, summary, url, source, fetched_at)
            VALUES (:advisory_id,:cve_id,:ecosystem,:package,:range_raw,:range_normalized,
                    :first_patched,:severity,:cvss,:kev,:published_at,:summary,:url,:source,:fetched_at)
            ON CONFLICT(advisory_id, ecosystem, package, range_raw) DO UPDATE SET
                cve_id=excluded.cve_id, range_normalized=excluded.range_normalized,
                first_patched=excluded.first_patched, severity=excluded.severity,
                cvss=excluded.cvss, kev=excluded.kev, published_at=excluded.published_at,
                summary=excluded.summary, url=excluded.url, source=excluded.source,
                fetched_at=excluded.fetched_at"""
        with self.tx() as db:
            db.executemany(sql, rows)
        return len(rows)

    def advisories_for_package(self, ecosystem: str, package: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            """SELECT * FROM advisory_range WHERE ecosystem=? AND package=?
               ORDER BY published_at DESC""", (ecosystem, package))]

    # ------------------------------------------------------------ 匹配结论

    def replace_findings(self, run_id: str, findings: list[dict[str, Any]]) -> None:
        sql = """INSERT OR REPLACE INTO exposure_finding
            (finding_id, asset_id, advisory_id, cve_id, component, ecosystem,
             installed_version, range_raw, first_patched, severity, cvss, priority,
             match_reason, evidence_hash, advisory_url, published_at, summary,
             status, run_id, created_at)
            VALUES (:finding_id,:asset_id,:advisory_id,:cve_id,:component,:ecosystem,
                    :installed_version,:range_raw,:first_patched,:severity,:cvss,:priority,
                    :match_reason,:evidence_hash,:advisory_url,:published_at,:summary,
                    'open',:run_id,:created_at)"""
        with self.tx() as db:
            db.executemany(sql, [{**f, "run_id": run_id} for f in findings])

    def list_findings(self, priority: str = "", asset_id: str = "") -> list[dict[str, Any]]:
        wsql = ["""NOT EXISTS (
            SELECT 1 FROM asset_candidate AS c
            LEFT JOIN asset_component AS a ON a.asset_id=c.candidate_id
            WHERE c.candidate_id=exposure_finding.asset_id
              AND (c.status!='confirmed' OR a.asset_id IS NULL
                   OR a.version!=exposure_finding.installed_version)
        )"""]
        params = []
        if priority:
            wsql.append("priority=?")
            params.append(priority)
        if asset_id:
            wsql.append("asset_id=?")
            params.append(asset_id)
        where = (" WHERE " + " AND ".join(wsql)) if wsql else ""
        return [dict(r) for r in self.db.execute(
            f"""SELECT * FROM exposure_finding{where}
                ORDER BY CASE priority WHEN 'P1' THEN 1 WHEN 'P2' THEN 2
                         WHEN 'P3' THEN 3 ELSE 4 END, cvss DESC""", params)]

    def findings_by_ids(self, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        return [dict(r) for r in self.db.execute(
            f"SELECT * FROM exposure_finding WHERE finding_id IN ({marks})", ids)]

    # ------------------------------------------------------------ 工单

    def insert_ticket(self, t: dict[str, Any]) -> None:
        """幂等写入：同一批结论重跑 draft 时更新草稿，不因主键冲突中断。

        只在原状态为 draft 时允许覆盖——已提交审批的单子必须保持不变，
        否则等于绕过审批改了内容。
        """
        cols = ["ticket_id", "title", "app_name", "owner", "priority", "status",
                "finding_ids", "evidence_hash", "evidence_json", "impact", "remediation",
                "rollback", "verification", "approver", "created_at", "updated_at"]
        updates = ",".join(f"{c}=excluded.{c}" for c in cols
                           if c not in {"ticket_id", "created_at", "status"})
        with self.tx() as db:
            existing = db.execute("SELECT status FROM change_ticket WHERE ticket_id=?",
                                  (t["ticket_id"],)).fetchone()
            if existing and existing["status"] != "draft":
                raise ValueError(
                    f"工单 {t['ticket_id']} 已处于 {existing['status']}，不允许覆盖草稿内容")
            db.execute(
                f"INSERT INTO change_ticket({','.join(cols)}) "
                f"VALUES ({','.join(':' + c for c in cols)}) "
                f"ON CONFLICT(ticket_id) DO UPDATE SET {updates}",
                {c: t[c] for c in cols})

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT * FROM change_ticket WHERE ticket_id=?",
                              (ticket_id,)).fetchone()
        return dict(row) if row else None

    def list_tickets(self, status: str = "") -> list[dict[str, Any]]:
        sql = "SELECT * FROM change_ticket"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY created_at DESC"
        return [dict(r) for r in self.db.execute(sql, params)]

    def update_ticket(self, ticket_id: str, **fields: Any) -> None:
        if not fields:
            return
        sets = ",".join(f"{k}=:{k}" for k in fields)
        with self.tx() as db:
            db.execute(f"UPDATE change_ticket SET {sets} WHERE ticket_id=:ticket_id",
                       {**fields, "ticket_id": ticket_id})

    def add_event(self, ticket_id: str, action: str, actor: str, role: str,
                  comment: str, from_status: str, to_status: str, now: str) -> None:
        with self.tx() as db:
            db.execute("""INSERT INTO ticket_event
                (ticket_id, action, actor, role, comment, from_status, to_status, created_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (ticket_id, action, actor, role, comment, from_status, to_status, now))

    def ticket_events(self, ticket_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM ticket_event WHERE ticket_id=? ORDER BY id", (ticket_id,))]

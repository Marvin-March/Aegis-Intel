"""采集本机的组件线索，并由人工审核后写入正式资产台账。"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Iterable

from packaging.version import InvalidVersion, Version

from .ingest import VALID_CRITICALITY, VALID_EXPOSURE
from .models import Asset, clean_version, norm_package
from .store import Store

SCOPE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")
PACKAGE_PATTERNS = {
    "pypi": re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*"),
    "npm": re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*", re.I),
}
SOURCES_BY_ECOSYSTEM = {"pypi": {"python-metadata"}, "npm": {"npm-lock", "npm-lock-dev"}}
ASSET_FIELDS = ("app_name", "owner", "environment", "exposure", "criticality", "business_unit")
REVIEW_COLUMNS = (
    "action", "candidate_id", "revision", "status", "scope", "ecosystem", "component",
    "observed_versions", "sources", "version", *ASSET_FIELDS, "reason",
)
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


@dataclass(frozen=True, order=True)
class Observation:
    ecosystem: str
    component: str
    version: str
    source: str
    location: str
    collector_host: str = ""


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def validate_scope(value: str) -> str:
    if not SCOPE_PATTERN.fullmatch(value):
        raise ValueError("scope 必须是稳定的部署标识，只允许 1–128 个字母、数字和 ._:/@-")
    return value


def _package(ecosystem: str, name: str) -> str:
    pattern = PACKAGE_PATTERNS.get(ecosystem)
    if pattern is None or not pattern.fullmatch(name):
        raise ValueError("组件标识无效，当前支持 pypi 和 npm")
    return norm_package(name, ecosystem)


def python_observations(site_paths: list[Path]) -> list[Observation]:
    """读取已安装发行包的元数据，不加载其中的 Python 模块。"""
    paths = [str(path.resolve(strict=True)) for path in site_paths]
    if any(not Path(path).is_dir() for path in paths):
        raise ValueError("--python-site 必须指向 site-packages 目录")
    distributions = metadata.distributions(path=paths) if paths else metadata.distributions()
    observations = []
    for dist in distributions:
        name = (dist.metadata.get("Name") or "").strip()
        if not PACKAGE_PATTERNS["pypi"].fullmatch(name):
            continue
        version = clean_version(dist.version)
        observations.append(Observation(
            "pypi", norm_package(name, "pypi"), version,
            "python-metadata", str(dist.locate_file("")),
        ))
    return sorted(set(observations))


def npm_observations(lock_file: Path) -> list[Observation]:
    """读取 npm 锁文件的包表。锁定版本属于构建证据，由用户确认部署版本。"""
    doc = json.loads(lock_file.read_text(encoding="utf-8-sig"))
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        raise ValueError("npm 锁文件缺少 packages 表，请使用 lockfileVersion 2 或 3")
    observations = []
    for location, info in packages.items():
        if not isinstance(info, dict):
            raise ValueError("npm 锁文件的包记录格式有误")
        if "node_modules/" not in location or info.get("link"):
            continue
        name = info.get("name") or location.rsplit("node_modules/", 1)[-1]
        version = info.get("version") or ""
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("npm 锁文件的组件名和版本必须是字符串")
        observations.append(Observation(
            "npm", _package("npm", name), clean_version(version),
            "npm-lock-dev" if info.get("dev") else "npm-lock",
            f"{lock_file.resolve()}#{location}",
        ))
    return sorted(set(observations))


def local_tcp_listeners() -> list[dict]:
    """从操作系统读取本机 TCP 监听状态，无连接请求。"""
    try:
        import psutil
    except ImportError as exc:
        raise ValueError("--listeners 需要安装 psutil") from exc

    try:
        connections = psutil.net_connections(kind="tcp")
    except psutil.Error as exc:
        raise ValueError("当前账号无法读取本机 TCP 监听状态") from exc

    listeners = {}
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        address, port = conn.laddr
        name = ""
        if conn.pid is not None:
            try:
                name = psutil.Process(conn.pid).name()
            except psutil.Error:
                pass
        listeners[(address, port, conn.pid)] = {
            "address": address, "port": port, "pid": conn.pid, "process": name,
        }
    return sorted(listeners.values(), key=lambda row: (row["address"], row["port"], row["pid"] or 0))


def _candidate_id(scope: str, ecosystem: str, component: str) -> str:
    material = _json([scope, ecosystem, component]).encode("utf-8")
    return "DISC-" + hashlib.sha256(material).hexdigest()[:24]


def snapshot_time(value: str) -> str:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise ValueError("采集时间必须包含时区")
    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")


def read_report(path: Path) -> tuple[str, str, list[Observation]]:
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        raise ValueError("采集报告格式有误，请导入 discover 生成的 JSON")
    scope = doc.get("scope")
    time = doc.get("collected_at")
    host = doc.get("collector_host")
    rows = doc.get("observations")
    if not all(isinstance(value, str) and value for value in (scope, time, host)) or not isinstance(rows, list):
        raise ValueError("采集报告缺少部署标识、采集时间、主机名或组件列表")
    observations = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("采集报告的组件行必须是对象")
        eco, name, version, source, location = (row.get(key) for key in
                                               ("ecosystem", "component", "version", "source", "location"))
        if not all(isinstance(value, str) for value in (eco, name, version, source, location)):
            raise ValueError("采集报告的组件字段必须是字符串")
        if source not in SOURCES_BY_ECOSYSTEM.get(eco, set()):
            raise ValueError("采集报告的组件来源和生态不匹配")
        observations.append(Observation(eco, _package(eco, name), clean_version(version), source, location, host))
    return validate_scope(scope), snapshot_time(time), observations


def stage_observations(store: Store, scope: str, observations: Iterable[Observation], now: str, *,
                       ordered_snapshot: bool = False,
                       reviewed_catalog: set[tuple[str, str]] | None = None) -> int:
    scope = validate_scope(scope)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for item in sorted(set(observations)):
        grouped.setdefault((item.ecosystem, item.component), []).append(asdict(item))

    rows = [
        (_candidate_id(scope, eco, package), scope, eco, package, _json(evidence), now, now)
        for (eco, package), evidence in grouped.items()
    ]
    with store.tx() as db:
        if ordered_snapshot:
            db.execute("BEGIN IMMEDIATE")
            last_seen = db.execute(
                """SELECT max(last_seen) FROM asset_candidate
                   WHERE scope=? AND observations_json!='[]'""", (scope,),
            ).fetchone()[0]
            if last_seen and last_seen > now:
                raise ValueError("该部署已有更新的采集报告，旧报告不能覆盖")
            if last_seen == now:
                return 0
        db.executemany(
            """INSERT INTO asset_candidate
                   (candidate_id, scope, ecosystem, component, observations_json, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(candidate_id) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   status=CASE WHEN observations_json != excluded.observations_json
                               THEN 'pending' ELSE status END,
                   revision=revision + (observations_json != excluded.observations_json),
                   observations_json=excluded.observations_json""",
            rows,
        )
        if reviewed_catalog:
            missing = reviewed_catalog.difference(grouped)
            for eco, component in sorted(missing):
                candidate_id = _candidate_id(scope, eco, component)
                evidence = _json([asdict(Observation(eco, component, "", "missing-from-snapshot", ""))])
                db.execute(
                    """UPDATE asset_candidate SET
                           last_seen=?,
                           revision=revision + (observations_json!=?),
                           status=CASE WHEN observations_json!=? THEN 'pending' ELSE status END,
                           observations_json=?
                       WHERE candidate_id=? AND observations_json!='[]'""",
                    (now, evidence, evidence, evidence, candidate_id),
                )
    return len(rows)


def _sheet_text(value: str) -> str:
    return "'" + value if value.lstrip(" ").startswith(FORMULA_PREFIXES) else value


def _input_text(value: str) -> str:
    if value.startswith("'") and value[1:].lstrip(" ").startswith(FORMULA_PREFIXES):
        value = value[1:]
    return value.strip()


def export_review(store: Store, output: Path, scope: str | None = None, *,
                  include_reviewed: bool = False) -> int:
    columns = ", ".join(f"a.{name}" for name in ASSET_FIELDS)
    rows = store.db.execute(
        f"""SELECT c.*, a.version AS confirmed_version, {columns} FROM asset_candidate AS c
            LEFT JOIN asset_component AS a ON a.asset_id=c.candidate_id
            WHERE (? OR c.status='pending') AND (? IS NULL OR c.scope=?)
            ORDER BY c.scope, c.ecosystem, c.component""", (include_reviewed, scope, scope),
    ).fetchall()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, REVIEW_COLUMNS)
        writer.writeheader()
        for candidate in rows:
            evidence = json.loads(candidate["observations_json"])
            versions = sorted({item["version"] for item in evidence if item["version"]})
            detected_version = versions[0] if len(versions) == 1 else ""
            row = {
                "candidate_id": candidate["candidate_id"],
                "revision": str(candidate["revision"]),
                "status": candidate["status"],
                "scope": candidate["scope"],
                "ecosystem": candidate["ecosystem"],
                "component": candidate["component"],
                "observed_versions": " | ".join(versions),
                "sources": " | ".join(sorted({item["source"] for item in evidence})),
                "version": ((candidate["confirmed_version"] or "")
                            if candidate["status"] == "confirmed" else detected_version),
                **{name: candidate[name] or "" for name in ASSET_FIELDS},
            }
            writer.writerow({name: _sheet_text(value) for name, value in row.items()})
    return len(rows)


def _confirmed_asset(candidate, evidence: list[dict], row: dict[str, str], actor: str, now: str) -> dict:
    required = ("version", "app_name", "owner", "environment", "exposure", "criticality")
    missing = [field for field in required if not row.get(field)]
    if missing:
        raise ValueError("缺少人工确认字段: " + ", ".join(missing))
    if row["exposure"] not in VALID_EXPOSURE or row["criticality"] not in VALID_CRITICALITY:
        raise ValueError("exposure 或 criticality 取值无效")
    version = clean_version(row["version"])
    try:
        Version(version)
    except InvalidVersion as exc:
        raise ValueError("版本无法被当前研判引擎解析") from exc
    versions = {item["version"] for item in evidence if item["version"]}
    if (versions != {version} or not any(item["source"] == "python-metadata" for item in evidence)):
        if not row.get("reason"):
            raise ValueError("版本冲突、修正版本、锁文件确认或手工补录须填写 reason")

    provenance = _json({
        "scope": candidate["scope"],
        "revision": candidate["revision"],
        "observations": evidence,
        "reviewed_by": actor,
        "reason": row.get("reason", ""),
    })
    asset = Asset(
        asset_id=candidate["candidate_id"],
        ecosystem=candidate["ecosystem"],
        component=candidate["component"],
        version=version,
        source="discovery-reviewed" if evidence else "manual-review",
        **{name: row.get(name, "") for name in ASSET_FIELDS},
    ).normalized()
    return {**asdict(asset), "detected_at": candidate["last_seen"], "evidence_json": provenance}


def apply_reviews(store: Store, review_file: Path, actor: str, now: str) -> dict[str, int]:
    if not actor.strip():
        raise ValueError("请填写审核人 --actor")
    actor = actor.strip()
    counts = dict.fromkeys(("confirm", "reject", "add"), 0)
    with review_file.open(encoding="utf-8-sig", newline="") as handle, store.tx() as db:
        reader = csv.DictReader(handle, strict=True)
        if "action" not in (reader.fieldnames or ()):
            raise ValueError("审核表缺少 action 列，请使用 review-export 生成的表头")
        db.execute("BEGIN IMMEDIATE")
        for line, raw in enumerate(reader, start=2):
            if None in raw:
                raise ValueError(f"第 {line} 行: CSV 列数超出表头")
            row = {key: _input_text(value or "") for key, value in raw.items()}
            action = row["action"]
            if not action:
                continue
            try:
                if action not in counts:
                    raise ValueError("action 必须为 confirm、reject 或 add")
                candidate_id = row.get("candidate_id", "")
                if action == "add":
                    if candidate_id or row.get("revision"):
                        raise ValueError("手工补录时 candidate_id 和 revision 应留空")
                    scope = validate_scope(row.get("scope", ""))
                    eco = row.get("ecosystem", "")
                    component = _package(eco, row.get("component", ""))
                    candidate_id = _candidate_id(scope, eco, component)
                    inserted = db.execute(
                        """INSERT OR IGNORE INTO asset_candidate
                           (candidate_id, scope, ecosystem, component, observations_json, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, '[]', ?, ?)""",
                        (candidate_id, scope, eco, component, now, now),
                    )
                    if not inserted.rowcount:
                        raise ValueError("该部署内已有同名候选，请使用现有记录审核")

                candidate = db.execute(
                    "SELECT * FROM asset_candidate WHERE candidate_id=?", (candidate_id,),
                ).fetchone()
                if candidate is None:
                    raise ValueError("候选不存在，请重新导出")
                if action != "add":
                    if row.get("revision") != str(candidate["revision"]):
                        raise ValueError("采集证据或审核记录已变化，请重新导出审核表")
                    if any(row.get(key) != candidate[key] for key in ("scope", "ecosystem", "component")):
                        raise ValueError("候选的 scope、ecosystem、component 由采集记录确定")
                evidence = json.loads(candidate["observations_json"])
                if action == "reject":
                    if not row.get("reason"):
                        raise ValueError("驳回须填写 reason")
                    status, event_evidence = "rejected", candidate["observations_json"]
                else:
                    asset = _confirmed_asset(candidate, evidence, row, actor, now)
                    store.upsert_assets([asset], now, connection=db)
                    status, event_evidence = "confirmed", _json(asset)
                db.execute(
                    "UPDATE asset_candidate SET status=?, revision=revision+1 WHERE candidate_id=?",
                    (status, candidate_id),
                )
                db.execute(
                    """INSERT INTO asset_review_event
                       (candidate_id, revision, action, actor, reason, evidence_json, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (candidate_id, candidate["revision"], action, actor, row.get("reason", ""), event_evidence, now),
                )
                counts[action] += 1
            except ValueError as exc:
                raise ValueError(f"第 {line} 行: {exc}") from exc
    return counts

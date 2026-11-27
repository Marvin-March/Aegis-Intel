"""Configuration, SQLite and HTTP primitives shared by the integration scripts."""


import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


UNKNOWN = "未知"


def load_env(path: Path) -> dict:
    if not path.is_file():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and re.fullmatch(r"[A-Z][A-Z0-9_]*", key.strip()):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            values[key.strip()] = value
    return values


def timestamp(when=None) -> str:
    return (when or datetime.now(UTC)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def text_value(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json_text(value)
    return str(value).strip()


def number(value, maximum):
    try:
        parsed = float(value)
        return parsed if 0 <= parsed <= maximum else None
    except (TypeError, ValueError):
        return None


def flag(value):
    if value is None or str(value).strip() == "":
        return None
    return str(value).strip().lower() in {"1", "true", "yes"}


def source_url(value):
    value = text_value(value)
    try:
        url = urlsplit(value)
        if (
            url.scheme in {"http", "https"} and url.hostname
            and not url.username and not url.password
            and not any(char.isspace() or ord(char) < 32 for char in value)
        ):
            return value
    except ValueError:
        pass
    return None


def severity_for(cvss):
    if cvss is None:
        return UNKNOWN
    if cvss >= 9:
        return "CRITICAL"
    if cvss >= 7:
        return "HIGH"
    if cvss >= 4:
        return "MEDIUM"
    return "LOW" if cvss > 0 else "NONE"


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    cvss: float | None = None
    severity: str = ""
    kev: bool | None = None
    epss: float | None = None
    cpes: tuple[str, ...] = ()
    ai_related: bool | None = None
    summary_zh: str = ""
    attack_type: str = ""
    affected_component: str = ""
    affected_versions: str = ""
    remediation_zh: str = ""
    url: str | None = None

    @classmethod
    def from_row(cls, row):
        raw = dict(row)
        try:
            enriched = json.loads(raw.get("enrich_json") or "{}")
        except (TypeError, ValueError):
            enriched = {}
        if not isinstance(enriched, dict):
            enriched = {}

        def field(name):
            return text_value(raw.get(name)) or text_value(enriched.get(name))

        cpes = text_value(raw.get("cpes"))
        try:
            cpes = json.loads(cpes)
        except ValueError:
            cpes = [cpes] if cpes else []
        if not isinstance(cpes, list):
            cpes = [cpes] if isinstance(cpes, str) else []
        cve_id = raw["cve_id"].strip().upper()
        cvss = number(raw.get("cvss"), 10)
        return cls(
            cve_id=cve_id,
            cvss=cvss,
            severity=field("severity").upper() or severity_for(cvss),
            kev=flag(raw.get("kev")),
            epss=number(raw.get("epss"), 1),
            cpes=tuple(cpe for cpe in cpes if isinstance(cpe, str) and cpe.startswith("cpe:")),
            ai_related=flag(raw.get("ai_related")),
            summary_zh=field("summary_zh"),
            attack_type=field("attack_type"),
            affected_component=field("affected_component"),
            affected_versions=field("affected_versions"),
            remediation_zh=field("remediation_zh"),
            url=source_url(raw.get("url")) or source_url(raw.get("record_url"))
            or f"https://www.cve.org/CVERecord?id={cve_id}",
        )

    def details(self):
        kev = {True: "是（已列入 CISA KEV）", False: "未列入 CISA KEV", None: UNKNOWN}
        return {
            "风险等级": self.severity or severity_for(self.cvss),
            "CVSS": f"{self.cvss:g}" if self.cvss is not None else UNKNOWN,
            "已知在野利用": kev[self.kev],
            "EPSS": f"{self.epss:.2%}" if self.epss is not None else UNKNOWN,
            "攻击类型": self.attack_type or UNKNOWN,
            "受影响组件": self.affected_component or ", ".join(self.cpes) or UNKNOWN,
            "受影响版本": self.affected_versions or UNKNOWN,
            "中文摘要": self.summary_zh or UNKNOWN,
            "修复建议": self.remediation_zh or UNKNOWN,
        }


def columns(db, table):
    # table names are internal constants, never configuration or user input.
    return {row[1] for row in db.execute(f"PRAGMA table_info({table})")}


def read_vulnerabilities(db: sqlite3.Connection, since_days: int) -> list[Vulnerability]:
    meta = columns(db, "vuln_meta")
    if "cve_id" not in meta:
        return []
    records = columns(db, "records")
    join, record_url = "", "NULL"
    dates = ["julianday(v.updated_at)"] if "updated_at" in meta else []
    if "id" in records:
        join = """LEFT JOIN records r ON r.id = COALESCE(
            (SELECT id FROM records WHERE id='cve-'||v.cve_id),
            (SELECT id FROM records WHERE id='advisory-'||v.cve_id),
            (SELECT id FROM records WHERE id='ghsa-'||v.cve_id))"""
        record_url = "r.url" if "url" in records else "NULL"
        dates.extend(f"julianday(r.{name})" for name in ("crawl_time", "publish_time") if name in records)
    date = f"COALESCE({', '.join(dates)}, NULL)" if dates else "NULL"
    where = f"WHERE {date} >= julianday(?)" if since_days else ""
    cutoff = (datetime.now(UTC) - timedelta(days=since_days)).isoformat()
    params = (cutoff,) if since_days else ()
    rows = db.execute(
        f"SELECT v.*, {record_url} AS record_url FROM vuln_meta v {join} {where} "
        f"ORDER BY {date if dates else 'v.cve_id'} DESC, v.cve_id", params
    )
    items = {}
    for row in rows:
        if isinstance(row["cve_id"], str) and CVE_ID.fullmatch(row["cve_id"].strip().upper()):
            item = Vulnerability.from_row(row)
            items.setdefault(item.cve_id, item)
    return list(items.values())


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def http_url(value):
    url = source_url(value)
    if not url:
        raise ValueError("Invalid or missing HTTP endpoint")
    if urlsplit(url).fragment:
        raise ValueError("HTTP endpoint cannot contain a fragment")
    return url


def endpoint_identity(url):
    """Canonical host/port for a configured endpoint without disclosing its URL."""
    parsed = urlsplit(http_url(url))
    host = parsed.hostname.lower()
    host = f"[{host}]" if ":" in host else host
    if parsed.port and (parsed.scheme, parsed.port) not in {("http", 80), ("https", 443)}:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))


def target_key(config, identity):
    target = config.get("target_key", "")
    if target:
        if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", target):
            raise ValueError("Invalid target_key")
        return target
    return "sha256:" + digest(identity)


@dataclass(frozen=True)
class Delivery:
    status: str
    external_id: str | None = None
    reason: str = ""


def http_failure(code):
    # A timeout or a server/gateway error can follow a committed external write.
    state = "failed" if 400 <= code < 500 and code != 408 else "uncertain"
    return Delivery(state, reason=f"HTTP {code}")


def post(url, **kwargs):
    import requests

    # Some providers carry credentials in the URL. Never follow a redirect.
    return requests.post(url, allow_redirects=False, **kwargs)


def response_object(response):
    try:
        value = response.json()
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


class DispatchLog:
    def __init__(self, db, *, writable):
        self.db = db
        if writable:
            with db:
                db.execute("""CREATE TABLE IF NOT EXISTS integration_dispatch_log(
                    channel TEXT NOT NULL, target_key TEXT NOT NULL, cve_id TEXT NOT NULL,
                    external_id TEXT, status TEXT NOT NULL, dispatched_at TEXT NOT NULL,
                    PRIMARY KEY (channel, target_key, cve_id)
                )""")
        self.exists = bool(columns(db, "integration_dispatch_log"))

    def statuses(self, channel, key):
        if not self.exists:
            return {}
        return dict(self.db.execute(
            "SELECT cve_id,status FROM integration_dispatch_log WHERE channel=? AND target_key=?",
            (channel, key),
        ))

    def claim(self, channel, key, cve_ids):
        # Commit before crossing the network; the same SQLite file coordinates all workers.
        claimed = []
        with self.db:
            for cve_id in cve_ids:
                result = self.db.execute(
                    """INSERT INTO integration_dispatch_log
                        (channel,target_key,cve_id,status,dispatched_at) VALUES(?,?,?,'pending',?)
                       ON CONFLICT(channel,target_key,cve_id) DO UPDATE SET
                        status='pending', external_id=NULL, dispatched_at=excluded.dispatched_at
                       WHERE integration_dispatch_log.status='failed'""",
                    (channel, key, cve_id, timestamp()),
                )
                if result.rowcount:
                    claimed.append(cve_id)
        return claimed

    def finish(self, channel, key, outcomes):
        with self.db:
            self.db.executemany(
                """UPDATE integration_dispatch_log SET status=?, external_id=?, dispatched_at=?
                   WHERE channel=? AND target_key=? AND cve_id=? AND status='pending'""",
                [(outcome.status, outcome.external_id, timestamp(), channel, key, cve_id)
                 for cve_id, outcome in outcomes.items()],
            )

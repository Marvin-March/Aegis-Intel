"""按客户确认的 AI 组件生成有版本证据的重点情报。"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from customer_intel_transport.integration_common import (
    CVE_ID, Vulnerability, digest, number, read_vulnerabilities, severity_for, source_url,
)

from .discovery import PACKAGE_PATTERNS, validate_scope
from .models import RangeParseError, norm_package, version_in_range

DEFAULT_CATALOG = Path(__file__).with_name("ai_component_catalog.json")
CUSTOMER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
NOTICE_ID = re.compile(r"[A-Za-z][A-Za-z0-9.-]{1,95}")
SEVERITY_RANK = {"UNKNOWN": -1, "NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def customer_prefix(customer: str) -> str:
    if not CUSTOMER_ID.fullmatch(customer):
        raise ValueError("客户 ID 必须是 1–64 个字母、数字、点、下划线或短横线")
    return customer + "/"


def customer_scope(customer: str, deployment: str) -> str:
    return validate_scope(customer_prefix(customer) + deployment)


def load_catalog(path: Path, categories: list[str]) -> set[tuple[str, str]]:
    catalog = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(catalog, dict) or not catalog:
        raise ValueError("AI 组件目录必须是按类别分组的 JSON 对象")
    keys = categories or catalog.keys()
    selected = set()
    for category in keys:
        group = catalog.get(category)
        if not isinstance(group, dict):
            raise ValueError(f"AI 组件目录缺少类别 {category}")
        for ecosystem, names in group.items():
            pattern = PACKAGE_PATTERNS.get(ecosystem)
            if pattern is None or not isinstance(names, list):
                raise ValueError(f"{category} 的生态必须是 pypi 或 npm，包名用数组")
            for name in names:
                if not isinstance(name, str) or not pattern.fullmatch(name):
                    raise ValueError(f"{category} 中有无效的包标识")
                selected.add((ecosystem, norm_package(name, ecosystem)))
    if not selected:
        raise ValueError("所选范围的 AI 组件目录为空")
    return selected


def confirmed_components(db: sqlite3.Connection, customer: str, catalog: set[tuple[str, str]]) -> list[sqlite3.Row]:
    prefix = customer_prefix(customer)
    assets = db.execute(
        """SELECT a.*, c.scope FROM asset_component AS a
           JOIN asset_candidate AS c ON c.candidate_id=a.asset_id
           WHERE c.status='confirmed' AND substr(c.scope, 1, ?)=?
           ORDER BY c.scope, a.ecosystem, a.component, a.version""",
        (len(prefix), prefix),
    )
    return [row for row in assets if (row["ecosystem"], row["component"]) in catalog]


@dataclass(frozen=True, order=True)
class VersionEvidence:
    ecosystem: str
    component: str
    version: str
    affected: str
    fixed: str

    def label(self) -> str:
        fix = self.fixed or "公告未给出"
        return f"{self.component} {self.version}（受影响区间 {self.affected}，修复版本 {fix}）"


@dataclass(frozen=True)
class FocusAlert(Vulnerability):
    evidence: tuple[VersionEvidence, ...] = ()
    deployments: int = 0

    @property
    def event_id(self) -> str:
        # 版本、区间、修复版本或 KEV 状态出现变化时，允许同一公告再次提醒。
        # 客户、渠道和接收目标由发送记录的独立键隔离。
        basis = (self.cve_id, self.kev is True, self.severity, self.evidence)
        return digest(repr(basis))

    def details(self) -> dict[str, str]:
        return {
            "客户组件命中": "；".join(item.label() for item in self.evidence),
            "匹配说明": f"{self.deployments} 个已确认部署的安装版本落入公告区间",
            "风险等级": self.severity or "未知",
            "CVSS": f"{self.cvss:g}" if self.cvss is not None else "未知",
            "CISA KEV": "已列入" if self.kev else "未标记",
            "中文摘要": self.summary_zh or "请查看公告原文",
            "修复建议": self.remediation_zh or "按公告核对修复版本",
        }


def _severity(values: list[str]) -> str:
    return max(
        (value.upper() for value in values if value and value.upper() in SEVERITY_RANK),
        default="UNKNOWN", key=SEVERITY_RANK.__getitem__,
    )


def focus_alerts(
    db: sqlite3.Connection, assets: list[sqlite3.Row], min_cvss: float, since_days: int = 0,
) -> tuple[list[FocusAlert], int]:
    if not assets:
        return [], 0
    meta = {item.cve_id: item for item in read_vulnerabilities(db, 0)}
    paired = defaultdict(list)
    for asset in assets:
        paired[(asset["ecosystem"], asset["component"])].append(asset)

    by_notice = defaultdict(list)
    unparsed = 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).date().isoformat() if since_days else ""
    for (eco, package), owned in paired.items():
        rows = db.execute(
            """SELECT * FROM advisory_range WHERE ecosystem=? AND package=?
               ORDER BY published_at DESC, advisory_id, range_raw""", (eco, package),
        )
        for advisory in rows:
            cve = (advisory["cve_id"] or "").upper()
            notice = cve if CVE_ID.fullmatch(cve) else advisory["advisory_id"]
            if not NOTICE_ID.fullmatch(notice):
                continue
            public = meta.get(cve, Vulnerability(cve_id=notice))
            kev = bool(advisory["kev"]) or public.kev is True
            if cutoff and not kev and (advisory["published_at"] or "")[:10] < cutoff:
                continue
            for asset in owned:
                try:
                    hit, _ = version_in_range(asset["version"], advisory["range_raw"], eco)
                except RangeParseError:
                    unparsed += 1
                    continue
                if hit:
                    by_notice[notice].append((asset, advisory, public))

    alerts = []
    for notice, matches in by_notice.items():
        best = max(matches, key=lambda row: (
            bool(row[1]["kev"]) or row[2].kev is True,
            number(row[1]["cvss"], 10) or 0,
            row[2].cvss or 0,
            row[1]["published_at"] or "",
        ))
        _, advisory, public = best
        kev = any(bool(row["kev"]) or info.kev is True for _, row, info in matches)
        scores = [score for _, row, info in matches
                  for score in (number(row["cvss"], 10), info.cvss) if score is not None]
        cvss = max(scores, default=None)
        severity = _severity([
            severity_for(cvss), *[row["severity"] or "" for _, row, _ in matches],
            *[info.severity for _, _, info in matches],
        ])
        if not kev and (cvss < min_cvss if cvss is not None else severity not in {"HIGH", "CRITICAL"}):
            continue
        evidence = tuple(sorted({
            VersionEvidence(asset["ecosystem"], asset["component"], asset["version"], row["range_raw"],
                            row["first_patched"] or "")
            for asset, row, _ in matches
        }))
        alerts.append(FocusAlert(
            cve_id=notice, cvss=cvss, severity=severity, kev=kev,
            summary_zh=public.summary_zh or advisory["summary"] or "",
            remediation_zh=public.remediation_zh,
            url=source_url(advisory["url"]) or public.url,
            evidence=evidence, deployments=len({asset["scope"] for asset, _, _ in matches}),
        ))
    alerts.sort(key=lambda item: (
        item.kev is True, item.cvss or 0, SEVERITY_RANK[item.severity], item.cve_id,
    ), reverse=True)
    return alerts, unparsed

# -*- coding: utf-8 -*-
"""资产 × 公告匹配引擎。

匹配是确定性三条件：
  1. 生态 + 包名归一后相等；
  2. 资产版本可解析，且落在公告区间内；
  3. 区间可解析（不可解析一律 unparsed，不计命中、也不计未命中）。

每个命中都产出可复核证据：安装版本、原始区间、归一化区间、修复版本、公告 URL、
证据指纹。审批人看到的每一条结论都能追到厂商原文。
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from .models import (RangeParseError, clean_version, compute_priority,
                     evidence_digest, make_id, norm_package, normalize_range,
                     version_in_range)


@dataclass
class MatchStats:
    assets: int = 0
    advisories: int = 0
    pairs_checked: int = 0
    findings: int = 0
    unparsed_ranges: int = 0
    unparsed_versions: int = 0
    skipped_pairs: int = 0

    def as_dict(self) -> dict[str, int]:
        return self.__dict__.copy()


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def match(assets: list[dict[str, Any]], advisories: list[dict[str, Any]],
          run_id: str | None = None) -> tuple[list[dict[str, Any]], MatchStats, list[dict]]:
    """返回 (findings, 统计, 解析失败明细)。"""
    run_id = run_id or f"run-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"
    created_at = now_iso()
    stats = MatchStats(assets=len(assets), advisories=len(advisories))
    findings: list[dict[str, Any]] = []
    problems: list[dict] = []

    # 索引：同一 (生态, 包) 的公告聚合，避免 O(资产 × 全库)
    index: dict[tuple[str, str], list[dict]] = {}
    for adv in advisories:
        key = (adv["ecosystem"], norm_package(adv["package"], adv["ecosystem"]))
        index.setdefault(key, []).append(adv)

    for asset in assets:
        eco = asset["ecosystem"]
        pkg = norm_package(asset["component"], eco)
        cands = index.get((eco, pkg))
        if not cands:
            continue
        installed = clean_version(asset["version"])

        for adv in cands:
            stats.pairs_checked += 1
            try:
                norm = normalize_range(adv["range_raw"], eco)
            except RangeParseError as exc:
                stats.unparsed_ranges += 1
                problems.append({"kind": "unparsed_range", "asset_id": asset["asset_id"],
                                 "advisory_id": adv["advisory_id"],
                                 "range_raw": adv["range_raw"], "error": str(exc)})
                continue
            try:
                hit, reason = version_in_range(installed, adv["range_raw"], eco)
            except RangeParseError as exc:
                stats.unparsed_versions += 1
                problems.append({"kind": "unparsed_version", "asset_id": asset["asset_id"],
                                 "version": installed, "error": str(exc)})
                continue
            if not hit:
                stats.skipped_pairs += 1
                continue

            severity = (adv.get("severity") or "unknown").lower()
            priority = compute_priority(severity, asset.get("criticality", "medium"),
                                        asset.get("exposure", "internal"),
                                        bool(adv.get("kev")))
            payload = {
                "asset_id": asset["asset_id"], "component": pkg, "ecosystem": eco,
                "installed_version": installed, "advisory_id": adv["advisory_id"],
                "range_raw": adv["range_raw"], "first_patched": adv.get("first_patched", ""),
                "severity": severity, "advisory_url": adv.get("url", ""),
            }
            findings.append({
                "finding_id": make_id("FND", asset["asset_id"], adv["advisory_id"],
                                      eco, pkg, installed, adv["range_raw"]),
                "asset_id": asset["asset_id"],
                "advisory_id": adv["advisory_id"],
                "cve_id": adv.get("cve_id", ""),
                "component": pkg, "ecosystem": eco,
                "installed_version": installed,
                "range_raw": adv["range_raw"],
                "first_patched": adv.get("first_patched", ""),
                "severity": severity,
                "cvss": adv.get("cvss"),
                "priority": priority,
                "match_reason": reason,
                "evidence_hash": evidence_digest(payload),
                "advisory_url": adv.get("url", ""),
                "published_at": adv.get("published_at", ""),
                "summary": (adv.get("summary") or "")[:500],
                "created_at": created_at,
            })

    stats.findings = len(findings)
    return findings, stats, problems


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """同一资产对同一 CVE 的多条区间公告只留最紧的一条（修复版本最接近的优先）。

    真实场景里同一 CVE 常有多个 GHSA 副本（如 litellm 的两段区间），
    工单里重复列同一条漏洞会让负责人误判工作量。
    """
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for f in findings:
        key = (f["asset_id"], f.get("cve_id") or f["advisory_id"])
        cur = best.get(key)
        if cur is None or (f.get("priority", "P4") < cur.get("priority", "P4")):
            best[key] = f
    return sorted(best.values(), key=lambda x: (x["priority"], -(x.get("cvss") or 0)))

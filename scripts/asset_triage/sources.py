# -*- coding: utf-8 -*-
"""公告来源适配：把外部漏洞公告归一成 advisory_range 需要的结构化区间。

为什么需要这一层：主项目 vuln_meta.affected_versions 只有 `影响 <=1.82.4；升级 1.84.0 修复`
这样的自然语言文本，OSV 采集器也把 ranges 丢了。机器比对必须拿到 (package, range) 原语。

来源：
  ghsa  GitHub Security Advisory（有 CVE 映射与 first_patched_version，首选）
  osv   OSV.dev（覆盖更广，ranges 为 events 结构，需转换）
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

if TYPE_CHECKING:
    import requests

from .models import norm_ecosystem, norm_package

GHSA_API = "https://api.github.com/advisories"
OSV_API = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns"

_OSV_ECO = {
    "pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go",
    "crates.io": "crates.io", "nuget": "NuGet",
}


def _session(timeout: int = 30) -> requests.Session:
    import requests

    s = requests.Session()
    s.headers.update({"Accept": "application/vnd.github+json",
                      "User-Agent": "aegis-asset-triage/0.1"})
    s.request_timeout = timeout  # type: ignore[attr-defined]
    return s


# ------------------------------------------------------------------ GHSA

def osv_events_to_range(events: list[dict[str, Any]]) -> str:
    """OSV events → 单段比较式。OSV 用 introduced/fixed 表达开闭区间。

    多个完整区间时返回空串表示需要拆分——由调用方按段入库，避免合并出错。
    """
    segments: list[str] = []
    introduced: str | None = None
    for ev in events:
        if "introduced" in ev:
            introduced = ev["introduced"]
        elif "fixed" in ev:
            fixed = ev["fixed"]
            low = "" if introduced in (None, "0", "") else f">={introduced}"
            if low:
                segments.append(f"{low},<{fixed}")
            else:
                segments.append(f"<{fixed}")
            introduced = None
        elif "last_affected" in ev:
            low = "" if introduced in (None, "0", "") else f">={introduced},"
            segments.append(f"{low}<={ev['last_affected']}")
            introduced = None
    if introduced not in (None, "0", ""):
        segments.append(f">={introduced}")
    if len(segments) != 1:
        return ""
    return segments[0]


def fetch_ghsa(packages: Iterable[tuple[str, str]], per_page: int = 100,
               sleep: float = 1.0, max_pages: int = 3) -> tuple[list[dict], list[str]]:
    """按 (ecosystem, package) 拉取公告。返回 (归一化行, 告警)。

    GitHub 的 ecosystem 参数用 pip / npm；affects 传包名。
    """
    sess = _session()
    rows: list[dict] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for eco, pkg in packages:
        gh_eco = {"pypi": "pip", "npm": "npm"}.get(norm_ecosystem(eco), eco)
        for page in range(1, max_pages + 1):
            try:
                r = sess.get(GHSA_API, params={"ecosystem": gh_eco, "affects": pkg,
                                               "per_page": per_page, "page": page},
                             timeout=30)
            except Exception as e:  # 网络层失败不阻塞其它包
                warnings.append(f"ghsa {pkg} p{page}: {type(e).__name__}: {e}")
                break
            if r.status_code != 200:
                warnings.append(f"ghsa {pkg} p{page}: HTTP {r.status_code}")
                break
            batch = r.json()
            if not batch:
                break
            for adv in batch:
                key = adv.get("ghsa_id", "")
                if key in seen:
                    continue
                seen.add(key)
                publish = (adv.get("published_at") or "")[:10]
                severity = (adv.get("severity") or "unknown").lower()
                cvss_score = ((adv.get("cvss") or {}).get("score"))
                for vul in adv.get("vulnerabilities", []):
                    p = vul.get("package", {})
                    a_eco = norm_ecosystem(p.get("ecosystem"))
                    a_pkg = norm_package(p.get("name", ""), a_eco)
                    rng = vul.get("vulnerable_version_range") or ""
                    if not a_pkg or not rng:
                        continue
                    first = vul.get("first_patched_version") or ""
                    if isinstance(first, dict):
                        first = first.get("identifier") or ""
                    rows.append({
                        "advisory_id": key, "cve_id": adv.get("cve_id") or "",
                        "ecosystem": a_eco, "package": a_pkg,
                        "range_raw": rng, "range_normalized": "",
                        "first_patched": first or "",
                        "severity": severity, "cvss": cvss_score,
                        "kev": 0, "published_at": publish,
                        "summary": (adv.get("summary") or "")[:500],
                        "url": adv.get("html_url") or f"https://github.com/advisories/{key}",
                        "source": "ghsa", "fetched_at": "",
                    })
            if len(batch) < per_page:
                break
            time.sleep(sleep)
        time.sleep(sleep)
    return rows, warnings


# ------------------------------------------------------------------ OSV

def fetch_osv(packages: Iterable[tuple[str, str]], sleep: float = 0.3) -> tuple[list[dict], list[str]]:
    """OSV 按包查询，取 ranges 的 events 转成比较式；同一 advisory 多段区间拆多行。"""
    sess = _session()
    rows: list[dict] = []
    warnings: list[str] = []
    for eco, pkg in packages:
        o_eco = _OSV_ECO.get(norm_ecosystem(eco))
        if not o_eco:
            warnings.append(f"osv 不支持的生态: {eco}")
            continue
        try:
            r = sess.post(OSV_API, json={"package": {"name": pkg, "ecosystem": o_eco}},
                          timeout=30)
            vulns = r.json().get("vulns", []) if r.status_code == 200 else []
        except Exception as e:
            warnings.append(f"osv {pkg}: {type(e).__name__}: {e}")
            continue
        for v in vulns:
            vid = v.get("id", "")
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            sev = "unknown"
            for s in v.get("severity", []) or []:
                sev = (s.get("type") or "").lower() or sev
            published = (v.get("published") or "")[:10]
            for aff in v.get("affected", []) or []:
                ap = aff.get("package", {})
                a_eco = norm_ecosystem(ap.get("ecosystem"))
                a_pkg = norm_package(ap.get("name", ""), a_eco)
                if not a_pkg:
                    continue
                for rng in aff.get("ranges", []) or []:
                    if rng.get("type") not in {"SEMVER", "ECOSYSTEM", "PYPI"}:
                        continue
                    expr = osv_events_to_range(rng.get("events", []))
                    if not expr:
                        warnings.append(f"osv {vid} {a_pkg}: 多段区间需拆分，已跳过")
                        continue
                    rows.append({
                        "advisory_id": vid, "cve_id": aliases[0] if aliases else "",
                        "ecosystem": a_eco, "package": a_pkg,
                        "range_raw": expr, "range_normalized": "",
                        "first_patched": "", "severity": sev, "cvss": None,
                        "kev": 0, "published_at": published,
                        "summary": (v.get("summary") or "")[:500],
                        "url": f"https://osv.dev/vulnerability/{vid}",
                        "source": "osv", "fetched_at": "",
                    })
        time.sleep(sleep)
    return rows, warnings


# ------------------------------------------------------------------ 本地文件

def load_advisory_rows(path: str | Path) -> list[dict]:
    """从已落盘的 JSON 读取（离线/内网环境用导出件）。"""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    rows = data.get("advisories", data) if isinstance(data, dict) else data
    out = []
    for r in rows:
        out.append({
            "advisory_id": r.get("advisory_id") or r.get("ghsa_id") or r.get("id", ""),
            "cve_id": r.get("cve_id") or "",
            "ecosystem": norm_ecosystem(r.get("ecosystem")),
            "package": norm_package(r.get("package") or r.get("component", ""), r.get("ecosystem") or "pypi"),
            "range_raw": r.get("range_raw") or r.get("vulnerable_version_range", ""),
            "range_normalized": "", "first_patched": r.get("first_patched") or r.get("first_patched_version") or "",
            "severity": (r.get("severity") or "unknown").lower(),
            "cvss": r.get("cvss"), "kev": int(bool(r.get("kev"))),
            "published_at": r.get("published_at", ""),
            "summary": r.get("summary", ""), "url": r.get("url", ""),
            "source": r.get("source", "file"), "fetched_at": "",
        })
    return [r for r in out if r["package"] and r["range_raw"]]

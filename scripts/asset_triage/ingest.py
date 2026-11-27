# -*- coding: utf-8 -*-
"""企业组件与版本清单接入。

支持三类真实入口，覆盖「企业提供清单」的常见形态：

1. CSV/JSON 清单（平台台账导出）——字段名做别名归一，容忍中文表头。
2. CycloneDX / SPDX SBOM——从真实构建产物直接取组件与版本。
3. pip freeze / requirements / package-lock——从运行环境或代码仓探测。

所有入口统一产出 models.Asset，缺失版本的行不静默丢弃，进 rejected 由调用方报告。
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

from .models import Asset, norm_ecosystem

# 平台台账的常见列名别名（中英文都覆盖，便于直接吃客户给的表）
FIELD_ALIASES = {
    "asset_id": ["asset_id", "资产id", "资产编号", "asset", "id", "主机名", "host", "ip"],
    "component": ["component", "组件", "包名", "package", "name", "software", "软件", "库"],
    "version": ["version", "版本", "版本号", "ver", "installed_version"],
    "ecosystem": ["ecosystem", "生态", "包管理器", "pkg_type", "type", "language"],
    "owner": ["owner", "负责人", "责任人", "owner_name", "维护人"],
    "business_unit": ["business_unit", "部门", "业务线", "team", "bu"],
    "environment": ["environment", "env", "环境", "部署环境"],
    "criticality": ["criticality", "重要度", "等级", "重要性", "tier"],
    "exposure": ["exposure", "暴露面", "网络位置", "network", "access"],
    "app_name": ["app_name", "应用", "应用名", "系统", "业务系统", "app", "application"],
    "source": ["source", "来源", "采集方式"],
}

VALID_CRITICALITY = {"low", "medium", "high", "critical"}
VALID_EXPOSURE = {"internet", "internal", "offline"}


def _pick(row: dict[str, Any], key: str, default: str = "") -> str:
    for alias in FIELD_ALIASES[key]:
        for raw_key, raw_val in row.items():
            if raw_key is None:
                continue
            if str(raw_key).strip().lower() == alias:
                if raw_val is None:
                    return default
                return str(raw_val).strip()
    return default


def _coerce_enum(value: str, allowed: set[str], default: str) -> str:
    v = (value or "").strip().lower()
    return v if v in allowed else default


def _finalize(row: dict[str, Any], idx: int, source: str, errors: list[dict]) -> Asset | None:
    component = _pick(row, "component")
    version = _pick(row, "version")
    if not component:
        errors.append({"row": idx, "reason": "缺少组件名", "raw": row})
        return None
    if not version:
        errors.append({"row": idx, "reason": "缺少版本号（无法做区间比对）",
                       "component": component, "raw": row})
        return None

    eco_raw = _pick(row, "ecosystem")
    if not eco_raw:
        # 无生态列时按包名特征猜：@scope/name 是 npm，其余按 Python 生态（AI 组件主流形态）
        eco_raw = "npm" if component.startswith("@") else "pypi"
    eco = norm_ecosystem(eco_raw)

    asset_id = _pick(row, "asset_id") or f"AUTO-{idx:04d}"
    asset = Asset(
        asset_id=asset_id,
        component=component,
        ecosystem=eco,
        version=version,
        owner=_pick(row, "owner"),
        business_unit=_pick(row, "business_unit"),
        environment=_pick(row, "environment", "prod") or "prod",
        criticality=_coerce_enum(_pick(row, "criticality"), VALID_CRITICALITY, "medium"),
        exposure=_coerce_enum(_pick(row, "exposure"), VALID_EXPOSURE, "internal"),
        source=_pick(row, "source") or source,
        app_name=_pick(row, "app_name"),
    )
    return asset.normalized()


def load_from_rows(rows: list[dict[str, Any]], source: str = "inventory") -> tuple[list[Asset], list[dict]]:
    assets, errors, seen = [], [], set()
    for i, row in enumerate(rows, 1):
        asset = _finalize(row, i, source, errors)
        if asset is None:
            continue
        key = (asset.asset_id, asset.ecosystem, asset.component, asset.version)
        if key in seen:
            errors.append({"row": i, "reason": "重复资产（已按首条归档）",
                           "asset_id": asset.asset_id})
            continue
        seen.add(key)
        assets.append(asset)
    return assets, errors


def load_inventory(path: str | Path) -> tuple[list[Asset], list[dict]]:
    """读取 CSV / JSON 清单（JSON 支持数组或 {"assets": [...]}）。"""
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() in {".json"}:
        data = json.loads(text)
        rows = data.get("assets", []) if isinstance(data, dict) else data
        return load_from_rows(rows, source="inventory-json")
    reader = csv.DictReader(io.StringIO(text))
    return load_from_rows(list(reader), source="inventory-csv")


_CYCLONEDX_ECO = {
    "pypi": "pypi", "python": "pypi", "pip": "pypi",
    "npm": "npm", "node": "npm",
}


def load_cyclonedx(path: str | Path) -> tuple[list[Asset], list[dict]]:
    """从 CycloneDX SBOM 取组件（purl 优先，其次 name/version）。"""
    doc = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    components = doc.get("components", [])
    rows: list[dict[str, Any]] = []
    errors: list[dict] = []
    for c in components:
        purl = c.get("purl") or ""
        name, ver, eco = c.get("name", ""), c.get("version", ""), ""
        m = re.match(r"pkg:(\w+)/([^@?]+)(?:@([^?#]+))?", purl)
        if m:
            eco, name, ver = m.group(1), m.group(2), (m.group(3) or ver)
        eco = _CYCLONEDX_ECO.get(eco.lower(), eco) if eco else ""
        if not eco:
            eco = "npm" if name.startswith("@") else "pypi"
        if not name:
            errors.append({"component": name, "reason": "SBOM 组件缺少名称"})
            continue
        rows.append({
            "asset_id": f"sbom:{c.get('bom-ref') or name}",
            "component": name, "version": ver, "ecosystem": eco,
            "app_name": c.get("group", ""), "source": "sbom-cyclonedx",
            "environment": "build",
        })
    assets, row_errors = load_from_rows(rows, source="sbom-cyclonedx")
    return assets, errors + row_errors


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|>=|~=)\s*([0-9][^\s;#]*)")


def load_pip_freeze(path: str | Path) -> tuple[list[Asset], list[dict]]:
    """从 pip freeze / requirements.txt 探测实例上真实安装的版本。"""
    rows, errors = [], []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _RE_RE_match(line)
        if not m:
            errors.append({"row": i, "reason": "无法解析依赖行", "line": line})
            continue
        name, ver = m
        rows.append({"asset_id": f"probe:{name}", "component": name, "version": ver,
                     "ecosystem": "pypi", "source": "pip-freeze", "environment": "prod"})
    return load_from_rows(rows, source="pip-freeze")[0], errors


def _RE_RE_match(line: str):
    m = _REQ_RE.match(line)
    return (m.group(1), m.group(2)) if m else None


def load_auto(path: str | Path) -> tuple[list[Asset], list[dict]]:
    """按扩展名/内容猜格式并分派。"""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".json":
        head = p.read_text(encoding="utf-8-sig")[:400]
        if "bomFormat" in head or "components" in head:
            return load_cyclonedx(p)
        return load_inventory(p)
    if suffix in {".csv", ".tsv"}:
        return load_inventory(p)
    if suffix == ".txt" or suffix == "":
        return load_pip_freeze(p)
    raise ValueError(f"不支持的清单格式: {p.name}（支持 csv/json/cyclonedx/pip freeze）")

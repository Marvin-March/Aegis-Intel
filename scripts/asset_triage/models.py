# -*- coding: utf-8 -*-
"""资产暴露面研判（asset triage）——数据模型与版本区间归一化。

本模块补齐 Aegis Intel 从「漏洞情报」到「企业内受影响资产」之间缺失的一环：
把厂商公告里的结构化版本区间，与资产清单里的实际安装版本做确定性比对。

设计约束（与主项目一致）：
  1. 确定性优先：版本比较只走 packaging / 显式语法，不引入 LLM 猜测。
  2. 可溯源：每个匹配结论都带 range_raw、installed_version 与公告 URL。
  3. 可拒绝：区间无法解析时标记 unparsed，绝不默认「命中」。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any

# ---------------------------------------------------------------- 生态与版本

PEP440_ECOSYSTEMS = {"pypi", "pip", "python", "conda"}
SEMVER_ECOSYSTEMS = {"npm", "node", "yarn", "pnpm"}

# CI 内部常见写法 → PEP 440 可解析写法
_PEP440_ALIASES = {
    "rc": "rc", "alpha": "a", "beta": "b", "pre": "rc", "preview": "rc",
    "dev": "dev", "post": "post",
}


def norm_ecosystem(eco: str | None) -> str:
    e = (eco or "").strip().lower()
    if e in {"pypi", "pip", "python", "conda"}:
        return "pypi"
    if e in {"npm", "node", "yarn", "pnpm"}:
        return "npm"
    return e or "unknown"


def norm_package(name: str, ecosystem: str) -> str:
    """包名归一：PyPI 忽略大小写与 _ / . 差异；npm 保留 scope。"""
    n = (name or "").strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", n).lower()
    return n.lower()


_VER_RE = re.compile(r"\d+(?:\.\d+)*(?:[._-]?(?:a|b|rc|alpha|beta|pre|dev|post)\d*)?")


def clean_version(ver: str | None) -> str:
    """去掉 v 前缀、空格与环境后缀，保留 prerelease 段（3.12.0rc0 不能被截成 3.12.0）。"""
    v = (ver or "").strip()
    v = v.lstrip("vV=").strip()
    v = re.sub(r"\s+", "", v)
    return v


def is_parseable_version(ver: str) -> bool:
    try:
        from packaging.version import Version
        Version(clean_version(ver))
        return True
    except Exception:
        return False


def compare_versions(a: str, b: str) -> int:
    """返回 -1/0/1。不可解析时抛 ValueError，由调用方决定降级策略。"""
    from packaging.version import Version
    va, vb = Version(clean_version(a)), Version(clean_version(b))
    return (va > vb) - (va < vb)


# ---------------------------------------------------------------- 版本区间

class RangeParseError(ValueError):
    """区间无法安全解析——必须显式失败，不能当作命中或未命中。"""


def _translate_semver_range(raw: str) -> str:
    """把 npm 的 ^ / ~ / x 通配 与空格分隔的区间改写成逗号分隔的比较式。"""
    s = (raw or "").strip().lower()
    if not s:
        raise RangeParseError("空区间")

    # "1.2.3 - 2.3.4" 连字符区间（两侧带空格）
    m = re.fullmatch(r"(\S+)\s+-\s+(\S+)", s)
    if m:
        return f">={clean_version(m.group(1))},<={clean_version(m.group(2))}"

    parts: list[str] = []
    for token in re.split(r"\s*,\s*|\s+(?=[<>=^~])", s):
        token = token.strip()
        if not token:
            continue
        if token.startswith("^"):
            base = clean_version(token[1:])
            nums = re.findall(r"\d+", base)
            if not nums:
                raise RangeParseError(f"无法解析 caret 区间: {raw}")
            major = int(nums[0])
            minor = int(nums[1]) if len(nums) > 1 else 0
            patch = int(nums[2]) if len(nums) > 2 else 0
            if major > 0:
                upper = f"{major + 1}.0.0"
            elif minor > 0:
                upper = f"0.{minor + 1}.0"
            else:
                upper = f"0.0.{patch + 1}"
            parts += [f">={base}", f"<{upper}"]
        elif token.startswith("~"):
            base = clean_version(token[1:])
            nums = re.findall(r"\d+", base)
            if not nums:
                raise RangeParseError(f"无法解析 tilde 区间: {raw}")
            if len(nums) > 1:
                upper = f"{int(nums[0])}.{int(nums[1]) + 1}.0"
            else:
                upper = f"{int(nums[0]) + 1}.0.0"
            parts += [f">={base}", f"<{upper}"]
        elif token in {"*", "x", "latest", "any"}:
            continue
        else:
            # "<1.2.3" / ">= 1.0.0" / "= 1.2.3" / "1.2.3"
            m2 = re.fullmatch(r"(<=|>=|==|=|<|>)?\s*(v?[0-9][\w.\-+]*|v?\d+\.\d+\.\*|v?\d+\.x)", token)
            if not m2:
                raise RangeParseError(f"无法解析区间片段: {token!r}（原文 {raw!r}）")
            op = m2.group(1) or "=="
            ver = clean_version(m2.group(2))
            if ver.endswith(".*") or ver.endswith(".x"):
                base = ver[:-2]
                nums = [int(x) for x in re.findall(r"\d+", base)]
                upper_nums = nums[:-1] + [nums[-1] + 1] if nums else [1]
                parts += [f">={base}", f"<{'.'.join(str(x) for x in upper_nums)}"]
            else:
                parts.append(f"{op}{ver}")
    if not parts:
        raise RangeParseError(f"区间无有效比较式: {raw!r}")
    return ",".join(parts)


def normalize_range(raw: str, ecosystem: str) -> str:
    """把厂商区间文本归一成 packaging 认可的 specifier 串。

    Raises:
        RangeParseError: 无法安全归一（调用方应标记 unparsed 并跳过比对）。
    """
    eco = norm_ecosystem(ecosystem)
    s = re.sub(r"\s+", " ", (raw or "").strip())
    if not s:
        raise RangeParseError("空区间")

    # 统一 "||" 之外的 OR 只保留第一支（多支区间在披露中表示「任一支命中」，
    # 直接拆成多行再各自比对更安全；这里显式拒绝，避免静默丢分支）
    if "||" in s:
        raise RangeParseError(f"OR 区间需拆分后比对: {raw!r}")

    if eco == "pypi":
        # PEP 440 写法：允许 "<=1.3.8"、">=1.0,<2.0"、还允许 1.3.8 后缀 a/b/rc/dev
        s2 = re.sub(r"(?<![<>=!~])\b(v)(\d)", r"\2", s)
        s2 = s2.replace(" - ", ",") if re.fullmatch(r"\S+\s+-\s+\S+", s2) else s2
        spec = s2.replace(" ", "")
    else:
        spec = _translate_semver_range(s)

    try:
        from packaging.specifiers import SpecifierSet
        SpecifierSet(spec)
    except Exception as exc:
        raise RangeParseError(f"归一后仍非法: {spec!r}（原文 {raw!r}）") from exc
    return spec


def version_in_range(version: str, range_raw: str, ecosystem: str) -> tuple[bool, str]:
    """判断版本是否落在区间内。返回 (命中?, 可直接入证据的判定说明)。

    Raises:
        RangeParseError: 区间或版本不可解析。
    """
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version

    ver = clean_version(version)
    if not ver:
        raise RangeParseError("资产版本为空")
    try:
        v = Version(ver)
    except Exception as exc:
        raise RangeParseError(f"资产版本不可解析: {version!r}") from exc

    spec_str = normalize_range(range_raw, ecosystem)
    spec = SpecifierSet(spec_str)
    hit = spec.contains(v, prereleases=True)
    reason = (f"{ver} {'满足' if hit else '不满足'}厂商区间 `{range_raw}`"
              f"（归一化 `{spec_str}`）")
    return hit, reason


# ---------------------------------------------------------------- 资产与公告

@dataclass
class Asset:
    asset_id: str
    component: str
    ecosystem: str
    version: str
    owner: str = ""
    business_unit: str = ""
    environment: str = "prod"
    criticality: str = "medium"        # low/medium/high/critical
    exposure: str = "internal"          # internet/internal/offline
    source: str = "manual"              # manual/sbom/probe/pip-freeze
    detected_at: str = ""
    app_name: str = ""                  # 所属内部 AI 应用
    evidence: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "Asset":
        eco = norm_ecosystem(self.ecosystem)
        return Asset(
            asset_id=self.asset_id.strip(),
            component=norm_package(self.component, eco),
            ecosystem=eco,
            version=clean_version(self.version),
            owner=(self.owner or "").strip(),
            business_unit=(self.business_unit or "").strip(),
            environment=(self.environment or "prod").strip().lower(),
            criticality=(self.criticality or "medium").strip().lower(),
            exposure=(self.exposure or "internal").strip().lower(),
            source=self.source,
            detected_at=self.detected_at,
            app_name=self.app_name,
            evidence=dict(self.evidence or {}),
        )


@dataclass
class Advisory:
    advisory_id: str
    cve_id: str
    severities: str
    cvss: float | None
    published_at: str
    summary: str
    url: str
    source: str
    fetched_at: str
    affected: list[dict[str, Any]] = field(default_factory=list)  # {ecosystem,package,range_raw,first_patched}


@dataclass
class Finding:
    finding_id: str
    asset_id: str
    advisory_id: str
    cve_id: str
    severity: str
    cvss: float | None
    installed_version: str
    range_raw: str
    range_normalized: str
    first_patched: str
    match_reason: str
    evidence_hash: str
    advisory_url: str
    published_at: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
CRITICALITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def compute_priority(severity: str, criticality: str, exposure: str, kev: bool = False) -> str:
    """优先级 = 漏洞严重度 × 资产重要度 × 暴露面（确定性加权，可审计）。

    评分区间 1-4 对应 P4-P1，规则写死在代码里，便于审批人复核「为什么是 P1」。
    KEV（在野利用）单独抬档：已被实际利用的漏洞，即便资产等级不高也不能按
    P4/P3 排队——这是时间压力，不是影响面。
    """
    s = SEVERITY_WEIGHT.get((severity or "unknown").lower(), 0)
    c = CRITICALITY_WEIGHT.get((criticality or "unknown").lower(), 0)
    score = s + c
    if (exposure or "").lower() == "internet":
        score += 2
    elif (exposure or "").lower() == "internal":
        score += 1

    if kev:
        # 在野利用：至少 P2，且随资产重要度上抬，但不越过最高档的判定
        base = "P2" if c <= 2 else "P1"
        by_score = "P1" if score >= 9 else "P2" if score >= 7 else "P3"
        floor = TICKET_PRIORITY_ORDER.index(base)
        ranked = TICKET_PRIORITY_ORDER.index(by_score)
        return TICKET_PRIORITY_ORDER[min(floor, ranked)]

    if score >= 9:
        return "P1"
    if score >= 7:
        return "P2"
    if score >= 5:
        return "P3"
    return "P4"


TICKET_PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]


def min_priority(priorities: list[str]) -> str:
    """取最紧急的一档（P1 最高）。"""
    real = [p for p in priorities if p in TICKET_PRIORITY_ORDER]
    if not real:
        return "P4"
    return sorted(real, key=TICKET_PRIORITY_ORDER.index)[0]


def evidence_digest(payload: dict[str, Any]) -> str:
    """证据指纹：对固定的关键字段做规范化哈希，用于审批时校验证据是否过期。"""
    keys = ["asset_id", "component", "ecosystem", "installed_version",
            "advisory_id", "range_raw", "first_patched", "severity", "advisory_url"]
    canonical = {k: payload.get(k, "") for k in keys}
    blob = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def make_id(prefix: str, *parts: str) -> str:
    blob = "|".join(str(p) for p in parts)
    return f"{prefix}-{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:12].upper()}"

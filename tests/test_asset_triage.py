# -*- coding: utf-8 -*-
"""资产暴露面研判的单元测试。

重点覆盖三类「错了会出事故」的行为：
  1. 版本边界：区间闭开、prerelease、npm caret/tilde；
  2. 误报防护：包名跨生态不能混、不可解析必须显式失败；
  3. 审批安全：证据失效自动驳回、非审批人不能签字。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from asset_triage.matcher import dedupe_findings, match
from asset_triage.models import (RangeParseError, clean_version, compute_priority,
                                 norm_package, normalize_range, version_in_range)
from asset_triage.store import Store
from asset_triage import tickets as tk


# ---------------------------------------------------------------- 版本区间

@pytest.mark.parametrize("version,rng,expected", [
    ("1.3.5", "<= 1.3.8", True),
    ("1.3.8", "<= 1.3.8", True),
    ("1.3.9", "<= 1.3.8", False),
    ("1.4.0", "<1.4.0", False),
    ("1.3.9", "<1.4.0", True),
    ("5.2.0", ">= 4.49.0, <= 5.8.1", True),
    ("4.48.0", ">= 4.49.0, <= 5.8.1", False),
    ("3.15.0", ">= 3.12.0rc0, < 3.17.0", True),
    ("3.17.0", ">= 3.12.0rc0, < 3.17.0", False),
    ("3.16.9", ">= 3.12.0rc0, < 3.17.0", True),
])
def test_version_in_range_pep440(version, rng, expected):
    hit, reason = version_in_range(version, rng, "pypi")
    assert hit is expected
    assert version in reason


@pytest.mark.parametrize("version,rng,expected", [
    ("1.5.0", "^1.2.3", True),
    ("2.0.0", "^1.2.3", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("0.2.5", "^0.2.3", True),
    ("0.3.0", "^0.2.3", False),
    ("1.4.0", ">=1.0.0 <2.0.0", True),
    ("2.1.0", ">=1.0.0 <2.0.0", False),
])
def test_version_in_range_semver(version, rng, expected):
    hit, _ = version_in_range(version, rng, "npm")
    assert hit is expected


def test_prerelease_not_truncated():
    # 3.12.0rc0 不能被截成 3.12.0，否则会把「预发布起受影响」误判成「从 3.12.0 起」
    assert clean_version("3.12.0rc0") == "3.12.0rc0"
    hit, _ = version_in_range("3.11.0", ">= 3.12.0rc0, < 3.17.0", "pypi")
    assert hit is False


def test_v_prefix_stripped():
    assert clean_version("v1.2.3") == "1.2.3"
    hit, _ = version_in_range("v1.2.3", ">=1.2.0", "pypi")
    assert hit is True


@pytest.mark.parametrize("rng", ["", "   ", "foo bar", ">=1.0.0 || <0.5.0"])
def test_unparseable_range_raises(rng):
    # 必须显式失败：静默当命中会误报，静默当未命中会漏报
    with pytest.raises(RangeParseError):
        normalize_range(rng, "pypi")


def test_unparseable_version_raises():
    with pytest.raises(RangeParseError):
        version_in_range("not-a-version", "<1.0.0", "pypi")


# ---------------------------------------------------------------- 归一化

def test_package_name_normalization():
    assert norm_package("LangChain_Anthropic", "pypi") == "langchain-anthropic"
    assert norm_package("ruamel.yaml", "pypi") == "ruamel-yaml"
    # npm 的 scope 必须保留，否则 @scope/a 与 a 会被错误合并
    assert norm_package("@OpenAI/Agents", "npm") == "@openai/agents"


def test_cross_ecosystem_not_merged():
    """同名包在不同生态是不同东西，绝不能互相匹配。"""
    assets = [{"asset_id": "a1", "component": "openai", "ecosystem": "pypi",
               "version": "1.99.0", "owner": "x", "criticality": "high",
               "exposure": "internal", "app_name": "app", "environment": "prod"}]
    advisories = [{"advisory_id": "GHSA-x", "cve_id": "CVE-1", "ecosystem": "npm",
                   "package": "openai", "range_raw": "<99.0.0", "first_patched": "99.0.0",
                   "severity": "high", "cvss": 8.0, "kev": 0,
                   "published_at": "2026-01-01", "summary": "", "url": ""}]
    findings, stats, _ = match(assets, advisories)
    assert findings == []
    assert stats.pairs_checked == 0


# ---------------------------------------------------------------- 优先级

@pytest.mark.parametrize("sev,crit,expo,kev,expected", [
    ("critical", "critical", "internet", False, "P1"),
    ("critical", "medium", "internal", False, "P2"),
    ("low", "low", "offline", False, "P4"),
    ("low", "low", "offline", True, "P2"),
    ("high", "high", "internal", False, "P2"),
])
def test_priority_rules(sev, crit, expo, kev, expected):
    assert compute_priority(sev, crit, expo, kev) == expected


# ---------------------------------------------------------------- 匹配

def _mk(asset_id, comp, ver, eco="pypi", owner="张三", app="app",
        crit="high", expo="internal"):
    return {"asset_id": asset_id, "component": comp, "ecosystem": eco, "version": ver,
            "owner": owner, "criticality": crit, "exposure": expo,
            "app_name": app, "environment": "prod"}


def _adv(aid, pkg, rng, cve="CVE-2026-1", sev="high", eco="pypi", patched="1.2.0"):
    return {"advisory_id": aid, "cve_id": cve, "ecosystem": eco, "package": pkg,
            "range_raw": rng, "first_patched": patched, "severity": sev, "cvss": 8.1,
            "kev": 0, "published_at": "2026-02-01", "summary": "s", "url": "https://x"}


def test_match_produces_evidence():
    findings, stats, probs = match([_mk("A1", "langchain", "1.3.5")],
                                   [_adv("GHSA-1", "langchain", "<= 1.3.8")])
    assert len(findings) == 1
    f = findings[0]
    assert f["installed_version"] == "1.3.5"
    assert f["evidence_hash"] and len(f["evidence_hash"]) == 64
    assert "满足" in f["match_reason"]
    assert f["advisory_url"] == "https://x"
    assert probs == []


def test_match_skips_fixed_version():
    findings, stats, _ = match([_mk("A1", "langchain", "1.3.9")],
                               [_adv("GHSA-1", "langchain", "<= 1.3.8")])
    assert findings == []
    assert stats.skipped_pairs == 1


def test_match_reports_unparsed_range():
    findings, stats, probs = match([_mk("A1", "x", "1.0.0")],
                                   [_adv("GHSA-1", "x", "莫名其妙的区间")])
    assert findings == []          # 不可解析不得算命中
    assert stats.unparsed_ranges == 1
    assert probs[0]["kind"] == "unparsed_range"


def test_dedupe_keeps_highest_priority_per_cve():
    a = {"asset_id": "A1", "cve_id": "CVE-9", "advisory_id": "G1", "priority": "P3", "cvss": 5}
    b = {"asset_id": "A1", "cve_id": "CVE-9", "advisory_id": "G2", "priority": "P1", "cvss": 9}
    c = {"asset_id": "A1", "cve_id": "CVE-8", "advisory_id": "G3", "priority": "P2", "cvss": 7}
    out = dedupe_findings([a, b, c])
    assert len(out) == 2
    assert out[0]["priority"] == "P1"


# ---------------------------------------------------------------- 工单审批

@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "t.sqlite")
    s.upsert_assets([{**_mk("A1", "langchain", "1.3.5"), "evidence_json": "{}"}], "2026-01-01")
    s.upsert_advisories([{**_adv("GHSA-1", "langchain", "<= 1.3.8"),
                          "range_normalized": "<=1.3.8", "kev": 0,
                          "source": "ghsa", "fetched_at": "2026-01-01"}])
    findings, _, _ = match(s.list_assets(),
                           [dict(r) for r in s.db.execute("SELECT * FROM advisory_range")])
    s.replace_findings("r1", findings)
    yield s
    s.close()


def _draft(store, approver="李四"):
    ids = [f["finding_id"] for f in store.list_findings()]
    res = tk.build_draft(store, ids, approver=approver, actor="系统")
    t = res["tickets"][0]
    store.insert_ticket(t)
    store.add_event(t["ticket_id"], "create", "系统", "system", "", "", "draft", "t")
    return t


def test_ticket_has_evidence(store):
    t = _draft(store)
    assert t["owner"] == "张三"
    assert t["priority"] in {"P1", "P2"}
    assert len(t["evidence_hash"]) == 64
    assert not t["status"] == "pending_approval"    # 草稿不得自动进入审批


def test_submit_requires_approver(store):
    ids = [f["finding_id"] for f in store.list_findings()]
    res = tk.build_draft(store, ids, approver="", actor="系统")
    t = res["tickets"][0]
    store.insert_ticket(t)
    with pytest.raises(tk.TicketTransitionError, match="审批人"):
        tk.submit(store, t["ticket_id"], "张三")


def test_full_approval_flow(store):
    t = _draft(store)
    tid = t["ticket_id"]
    tk.submit(store, tid, "张三", "申请升级")
    assert store.get_ticket(tid)["status"] == "pending_approval"
    tk.decide(store, tid, "李四", True, "同意")
    assert store.get_ticket(tid)["status"] == "approved"
    tk.close(store, tid, "张三", "已完成")
    assert store.get_ticket(tid)["status"] == "closed"
    actions = [e["action"] for e in store.ticket_events(tid)]
    assert actions == ["create", "submit", "approve", "close"]


def test_only_named_approver_can_sign(store):
    t = _draft(store, approver="李四")
    tk.submit(store, t["ticket_id"], "张三", "申请")
    with pytest.raises(PermissionError):
        tk.decide(store, t["ticket_id"], "王五", True, "同意")


def test_decision_requires_comment(store):
    t = _draft(store)
    tk.submit(store, t["ticket_id"], "张三", "申请")
    with pytest.raises(tk.TicketTransitionError, match="意见"):
        tk.decide(store, t["ticket_id"], "李四", True, "  ")


def test_stale_evidence_auto_rejected(store):
    """资产已升到修复版本后，旧工单不能再被批准。"""
    t = _draft(store)
    tid = t["ticket_id"]
    tk.submit(store, tid, "张三", "申请")
    store.db.execute("UPDATE asset_component SET version='1.3.9' WHERE asset_id='A1'")
    store.db.commit()
    with pytest.raises(tk.TicketTransitionError, match="证据已失效"):
        tk.decide(store, tid, "李四", True, "同意")
    assert store.get_ticket(tid)["status"] == "rejected"
    events = store.ticket_events(tid)
    assert any(e["action"] == "auto_reject_stale" for e in events)


def test_cannot_approve_twice(store):
    t = _draft(store)
    tk.submit(store, t["ticket_id"], "张三", "申请")
    tk.decide(store, t["ticket_id"], "李四", True, "同意")
    with pytest.raises(tk.TicketTransitionError, match="不可审批"):
        tk.decide(store, t["ticket_id"], "李四", True, "再同意一次")


def test_redraft_cannot_overwrite_submitted_ticket(store):
    t = _draft(store)
    tk.submit(store, t["ticket_id"], "张三", "申请")
    with pytest.raises(ValueError, match="不允许覆盖"):
        store.insert_ticket(t)

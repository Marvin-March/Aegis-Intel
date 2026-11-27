# -*- coding: utf-8 -*-
"""带证据的工单草稿生成 + 负责人审批状态机。

两条硬约束，决定它能不能真的进企业变更流程：
  1. 工单只能由 open finding 生成，且必须写清 owner；无负责人不允许提交审批。
  2. 审批时重新校验 evidence_hash——如果资产版本或公告区间在审批期间变了，
     工单自动失效（rejected），审批人不会在过时证据上签字。
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .matcher import now_iso
from .models import (TICKET_PRIORITY_ORDER, evidence_digest, make_id,
                     min_priority)
from .store import ALLOWED_TRANSITIONS, Store, TicketTransitionError


def _fmt_evidence_block(f: dict[str, Any]) -> str:
    lines = [
        f"- **{f.get('cve_id') or f['advisory_id']}** · {f['component']} "
        f"`{f['installed_version']}`（{f['ecosystem']}）",
        f"  - 受影响区间：`{f['range_raw']}`",
        f"  - 建议修复版本：`{f.get('first_patched') or '厂商未给出，需人工确认'}`",
        f"  - 严重度：{f['severity']}（CVSS {f.get('cvss') if f.get('cvss') is not None else '-'}）"
        f"，优先级 {f['priority']}",
        f"  - 判定依据：{f['match_reason']}",
        f"  - 公告来源：{f.get('advisory_url') or '-'}",
        f"  - 证据指纹：`{f.get('evidence_hash')}`",
    ]
    return "\n".join(lines)


def build_draft(store: Store, finding_ids: list[str], approver: str = "",
                rollback: str = "", verification: str = "",
                actor: str = "") -> dict[str, Any]:
    """按资产归属的应用/负责人聚合生成工单草稿。

    一个 owner 一张单：变更单是「一个人去改一个环境」，跨负责人合并会导致
    无人真正签字负责。
    """
    findings = store.findings_by_ids(finding_ids)
    if len(findings) != len(set(finding_ids)):
        missing = set(finding_ids) - {f["finding_id"] for f in findings}
        raise ValueError(f"存在无效 finding_id: {sorted(missing)}")

    assets = {a["asset_id"]: a for a in store.list_assets(confirmed_only=True)}
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for f in findings:
        a = assets.get(f["asset_id"])
        if not a or a["version"] != f["installed_version"]:
            raise ValueError(f"资产 {f['asset_id']} 待重新确认或版本已变更，请重新比对")
        owner = a.get("owner") or ""
        groups[(owner, a.get("app_name", ""), a.get("environment", "prod"))].append(f)

    created: list[dict[str, Any]] = []
    for (owner, app_name, env), group in groups.items():
        if not owner:
            raise ValueError(f"资产 {group[0]['asset_id']} 未填负责人，不能生成变更单")
        comps = sorted({(f["component"], f["installed_version"]) for f in group})
        priority = min_priority([f["priority"] for f in group])
        evidence_json = json.dumps(group, ensure_ascii=False, sort_keys=True)
        ehash = evidence_digest({
            "asset_id": ",".join(sorted({f["asset_id"] for f in group})),
            "component": ",".join(c for c, _ in comps),
            "ecosystem": ",".join(sorted({f["ecosystem"] for f in group})),
            "installed_version": ",".join(v for _, v in comps),
            "advisory_id": ",".join(sorted({f["advisory_id"] for f in group})),
            "range_raw": ",".join(sorted({f["range_raw"] for f in group})),
            "first_patched": ",".join(sorted({f.get("first_patched") or "" for f in group})),
            "severity": priority,
            "advisory_url": ",".join(sorted({f.get("advisory_url") or "" for f in group})),
        })
        ticket = {
            "ticket_id": make_id("CHG", owner, app_name, env,
                                 ",".join(sorted(f["finding_id"] for f in group))),
            "title": f"[{priority}] {app_name or 'AI 应用'} 组件漏洞修复："
                     + ", ".join(f"{c} {v}" for c, v in comps[:3])
                     + (f" 等 {len(comps)} 项" if len(comps) > 3 else ""),
            "app_name": app_name,
            "owner": owner,
            "priority": priority,
            "status": "draft",
            "finding_ids": json.dumps([f["finding_id"] for f in group], ensure_ascii=False),
            "evidence_hash": ehash,
            "evidence_json": evidence_json,
            "impact": _impact_text(app_name, env, group),
            "remediation": _remediation_text(group),
            "rollback": rollback or "升级前保留旧版本镜像与配置快照；异常时回滚到上一版本并保留日志。",
            "verification": verification or "升级后复跑本次比对（同一清单），确认对应区间不再命中；"
                                            "并对关键路径做一次冒烟验证。",
            "approver": approver,
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        created.append(ticket)

    return {"tickets": created, "groups": [
        {"owner": o, "app_name": a, "environment": e, "finding_ids": [f["finding_id"] for f in g]}
        for (o, a, e), g in groups.items()]}


def _impact_text(app_name: str, env: str, group: list[dict]) -> str:
    sev = sorted({f["severity"] for f in group})
    comps = sorted({f["component"] for f in group})
    return (f"{app_name or '该应用'}（环境：{env}）使用 {len(comps)} 个存在已知漏洞的组件，"
            f"涉及 {len(group)} 条受影响结论，严重度覆盖 {', '.join(sev)}。"
            f"受影响组件：{', '.join(comps[:8])}{' 等' if len(comps) > 8 else ''}。")


def _remediation_text(group: list[dict]) -> str:
    """按组件聚合：同一组件只需升一次，目标取所有命中公告里最高的修复版本。

    不同 CVE 常给出不同的 first_patched（如 3.17.0 / 3.17.2），逐个列会让执行人
    反复升级；合并到最高版本才是一次可执行的变更。
    """
    by_comp: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for f in group:
        by_comp[(f["component"], f["ecosystem"])].append(f)

    from packaging.version import Version, InvalidVersion

    lines: list[str] = []
    for (comp, eco), fs in sorted(by_comp.items(),
                                  key=lambda kv: TICKET_PRIORITY_ORDER.index(
                                      min_priority([f["priority"] for f in kv[1]]))):
        patched = [(f.get("first_patched") or "") for f in fs if f.get("first_patched")]
        target = ""
        if patched:
            try:
                target = max(patched, key=Version)
            except InvalidVersion:
                target = sorted(patched)[-1]
        comp_priority = min_priority([f["priority"] for f in fs])
        ids = ", ".join(sorted({(f.get("cve_id") or f["advisory_id"]) for f in fs}))
        lines.append(f"- **{comp}**（{eco}）：`{fs[0]['installed_version']}` → "
                     f"`{target or '需按公告人工确认'}`（{comp_priority}，共 {len(fs)} 条）")
        lines.append(f"  - 覆盖漏洞：{ids}")
        if not target:
            lines.append("  - ⚠ 厂商未给出修复版本：需评估临时缓解或替换方案后再变更")
        if len(patched) > 1 and len(set(patched)) > 1:
            lines.append(f"  - 各公告给出的修复版本：{', '.join(sorted(set(patched)))}；"
                         f"取最高 `{target}` 以一次覆盖全部")
        for f in sorted(fs, key=lambda x: TICKET_PRIORITY_ORDER.index(x["priority"]))[:4]:
            lines.append(f"  - {f.get('cve_id') or f['advisory_id']}：区间 `{f['range_raw']}`"
                         f"；{f.get('advisory_url') or '-'}")
        if len(fs) > 4:
            lines.append(f"  - 其余 {len(fs) - 4} 条见证据清单")
    return "\n".join(lines)


def render_markdown(ticket: dict[str, Any], findings: list[dict[str, Any]],
                    events: list[dict[str, Any]] | None = None) -> str:
    """产出可直接贴进 ITSM / 邮件的工单正文。"""
    lines = [
        f"# {ticket['title']}",
        "",
        "| 字段 | 值 |",
        "|---|---|",
        f"| 工单号 | `{ticket['ticket_id']}` |",
        f"| 状态 | {ticket['status']} |",
        f"| 优先级 | {ticket['priority']} |",
        f"| 应用 | {ticket.get('app_name') or '-'} |",
        f"| 负责人 | {ticket.get('owner') or '-'} |",
        f"| 审批人 | {ticket.get('approver') or '待指派'} |",
        f"| 证据指纹 | `{ticket.get('evidence_hash', '')}` |",
        f"| 创建时间 | {ticket.get('created_at', '')} |",
        "",
        "## 影响",
        "",
        ticket.get("impact", ""),
        "",
        "## 受影响项与证据",
        "",
    ]
    lines += [_fmt_evidence_block(f) for f in findings]
    lines += ["", "## 变更方案", "", ticket.get("remediation", ""), ""]
    lines += ["## 回滚方案", "", ticket.get("rollback", ""), ""]
    lines += ["## 验证方案", "", ticket.get("verification", ""), ""]

    if events:
        lines += ["## 审批记录", "", "| 时间 | 动作 | 角色 | 操作人 | 说明 |", "|---|---|---|---|---|"]
        for e in events:
            lines.append(f"| {e['created_at']} | {e['action']} | {e.get('role', '')} | "
                         f"{e.get('actor', '')} | {e.get('comment', '')} |")
        lines.append("")
    return "\n".join(lines)


def submit(store: Store, ticket_id: str, actor: str, comment: str = "") -> dict[str, Any]:
    t = store.get_ticket(ticket_id)
    if not t:
        raise ValueError(f"工单不存在: {ticket_id}")
    _assert_transition(t["status"], "pending_approval")
    if not t.get("owner"):
        raise TicketTransitionError("工单无负责人，不能提交审批")
    if not t.get("approver"):
        raise TicketTransitionError("工单未指定审批人，不能提交审批")
    # 提交前重算证据：资产版本若已变更，草稿即失效
    _assert_evidence_fresh(store, t)
    now = now_iso()
    store.update_ticket(ticket_id, status="pending_approval", updated_at=now, submitted_at=now)
    store.add_event(ticket_id, "submit", actor, "owner", comment,
                    t["status"], "pending_approval", now)
    return store.get_ticket(ticket_id) or {}


def decide(store: Store, ticket_id: str, approver: str, approve: bool,
           comment: str = "") -> dict[str, Any]:
    t = store.get_ticket(ticket_id)
    if not t:
        raise ValueError(f"工单不存在: {ticket_id}")
    if t["status"] != "pending_approval":
        raise TicketTransitionError(f"当前状态 {t['status']} 不可审批")
    if approver != (t.get("approver") or ""):
        raise PermissionError(f"审批人不匹配：本单审批人为 {t.get('approver')}")
    if not comment.strip():
        raise TicketTransitionError("审批必须填写意见（用于变更审计）")

    fresh, why = _evidence_fresh(store, t)
    if not fresh:
        now = now_iso()
        store.update_ticket(ticket_id, status="rejected", updated_at=now, decided_at=now,
                            approve_comment=f"证据已失效：{why}")
        store.add_event(ticket_id, "auto_reject_stale", "system", "system", why,
                        "pending_approval", "rejected", now)
        raise TicketTransitionError(f"证据已失效，工单自动驳回：{why}")

    to_status = "approved" if approve else "rejected"
    _assert_transition(t["status"], to_status)
    now = now_iso()
    store.update_ticket(ticket_id, status=to_status, updated_at=now, decided_at=now,
                        approver=approver, approve_comment=comment)
    store.add_event(ticket_id, "approve" if approve else "reject", approver,
                    "approver", comment, "pending_approval", to_status, now)
    return store.get_ticket(ticket_id) or {}


def close(store: Store, ticket_id: str, actor: str, comment: str = "") -> dict[str, Any]:
    t = store.get_ticket(ticket_id)
    if not t:
        raise ValueError(f"工单不存在: {ticket_id}")
    _assert_transition(t["status"], "closed")
    now = now_iso()
    store.update_ticket(ticket_id, status="closed", updated_at=now)
    store.add_event(ticket_id, "close", actor, "owner", comment, "approved", "closed", now)
    return store.get_ticket(ticket_id) or {}


def _assert_transition(from_status: str, to_status: str) -> None:
    if (from_status, to_status) not in ALLOWED_TRANSITIONS:
        raise TicketTransitionError(f"非法状态流转: {from_status} → {to_status}")


def _evidence_fresh(store: Store, ticket: dict[str, Any]) -> tuple[bool, str]:
    """重算：工单内每条 finding 的资产版本与公告区间是否仍与签发时一致。"""
    ids = json.loads(ticket.get("finding_ids") or "[]")
    assets = {a["asset_id"]: a for a in store.list_assets(confirmed_only=True)}
    for f in store.findings_by_ids(ids):
        a = assets.get(f["asset_id"])
        if not a:
            return False, f"资产 {f['asset_id']} 待重新确认或已从清单移除"
        if a["version"] != f["installed_version"]:
            return False, (f"资产 {f['asset_id']} 版本已变更为 {a['version']}"
                           f"（取证时为 {f['installed_version']}）")
        advisories = store.advisories_for_package(f["ecosystem"], f["component"])
        if not any(x["advisory_id"] == f["advisory_id"] and x["range_raw"] == f["range_raw"]
                   for x in advisories):
            return False, f"公告 {f['advisory_id']} 的区间已更新，需重新比对"
    return True, "ok"


def _assert_evidence_fresh(store: Store, ticket: dict[str, Any]) -> None:
    ok, why = _evidence_fresh(store, ticket)
    if not ok:
        raise TicketTransitionError(f"证据已失效，请重新比对后再提交：{why}")

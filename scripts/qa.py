#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qa.py —— 问答层入口

流程：search() 检索 → 拼 prompt（卡片在前 + 文本块带引用 + 拒答条款）→ LLM 生成
     → fabricate_check 拦编造（重生成一次 → 仍编则剔除）→ 返回最终答案。
Provider（2026-10-15 起）：优先硅基流动 SiliconFlow 托管的 DeepSeek（无指令级安全审核，
     安全语料可正常问答），再到官方 DeepSeek，最后 GLM 兜底；全部失败才走结构化降级。
拒答：检索不足（无块无卡片）或点查未命中时直接拒答，不调 LLM。

用法:
    uv run python scripts/qa.py "针对 MCP 工具链的供应链攻击有哪些？"
    uv run python scripts/qa.py "CVE-2026-59822 是什么？" --show-steps
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from search import search, CVE_RE, article_enrich  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PROVIDERS = {
    "glm": {"base": "https://open.bigmodel.cn/api/paas/v4",
            "model": "glm-4-flash", "env": "GLM_API_KEY"},   # 稳定档；--model 可切 4.5-flash
    # 安全语料换成无审核的渠道：GLM 内容审核会拦"攻击/越狱/RCE"等词（2026-10-15 实测 400/1301），
    # 后端走 DeepSeek 系模型。每天几十条生成，质价比排序：硅基流动(SiliconFlow) → 官方 DeepSeek → GLM 兜底。
    "siliconflow": {"base": "https://api.siliconflow.cn/v1",
                    "model": "deepseek-ai/DeepSeek-V3.2", "env": "SILICONFLOW_API_KEY",
                    "note": "硅基流动，DeepSeek 托管，无指令级安全审核"},
    "deepseek": {"base": "https://api.deepseek.com",
                 "model": "deepseek-chat", "env": "DEEPSEEK_API_KEY"},
}
REFUSAL = "根据现有情报库无法回答此问题。"

SYSTEM_PROMPT = """你是高级网络安全情报专家，负责基于情报库检索结果输出专业深度分析，而非简单罗列。

【回答结构要求（必须严格遵守）】
按以下三段式大纲组织回答：
1. 【宏观态势综述】先用 1-2 句概括该主题的整体安全态势与共性特征（趋势、影响面、关键结论）
2. 【核心漏洞/事件分类剖析】按技术脉络归纳分点——每点代表一个技术方向或一类漏洞/事件，
   必须融合检索文本、富化摘要与漏洞卡片中的技术细节（漏洞机制、攻击手法、受影响组件），
   严禁只复述文章标题或机械堆砌原文切片
3. 【安全防护建议】基于卡片修复建议与文本中的防御措施，给出可操作的分点建议

写作要求（深度论述，禁止偷懒）：
- 【核心剖析】的每个点必须是 3-6 句的完整段落，段落内必须覆盖三要素：
  技术机制（为什么成立）→ 攻击手法/利用方式（怎么打）→ 实际影响（打了会怎样），
  三要素缺一不可；段落之间用空行分隔，禁止用"1. 2. 3."编号列表代替段落论述
- 严禁"标题加一句话"的伪分析；严禁只复述卡片/文本原句而不展开解释；
  必须把富化摘要、实体信息与原文细节连贯串联、补充展开
- 全文 1000-1500 字；中文，专业措辞，观点有出处

【引用与边界】
- 每个论断标注引用编号 [n]（检索文本块）或 [卡n]（漏洞卡片）
- 涉及 CVE 编号只能使用卡片或文本中出现的，禁止编造
- 只依据给定的检索结果，禁止使用检索结果之外的知识
- 检索结果不足以回答时，直接说"{refusal}\""""


def load_dotenv() -> dict:
    env = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def fabricate_ids(answer: str, db: sqlite3.Connection) -> list[str]:
    """回答中不在库的 CVE 编号 = 编造（与 enrich_llm 铁律同源）。"""
    ids = [c.upper() for c in CVE_RE.findall(answer)]
    if not ids:
        return []
    q = ",".join("?" * len(ids))
    known = {r[0] for r in db.execute(
        f"SELECT cve_id FROM vuln_meta WHERE cve_id IN ({q})", ids)}
    return [i for i in ids if i not in known]


def call_llm(messages: list[dict], provider: str, model: str, key: str,
             temperature: float = 0.2, max_tokens: int = 2000, timeout: int = 180) -> str:
    """通用 chat/completions 调用（OpenAI 兼容协议，glm/deepseek 通用）。"""
    import requests
    base = PROVIDERS[provider]["base"]
    r = requests.post(f"{base}/chat/completions",
                      headers={"Authorization": f"Bearer {key}"},
                      json={"model": model, "temperature": temperature,
                            "messages": messages, "max_tokens": max_tokens},
                      timeout=timeout)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


# 多轮追问的"焦点"提取（2026-10-15）：指代短句（"它的攻击链路是怎样的"）里
# 追问方向藏在词里——不显式点出，模型会把漏洞全貌复述一遍（用户实测反馈"没针对性"）。
_FOCUS_RULES = (
    (("攻击链", "攻击链路", "攻击路径", "链路", "攻击方式", "怎么打", "利用方式",
      "利用手法", "利用方法", "利用细节", "攻击细节", "攻击过程", "利用链", "怎么利用",
      "漏洞利用"),
     "攻击链路与利用方式"),
    (("为什么", "原理", "机制", "原因", "根源", "根因", "底层"), "漏洞产生的技术机理"),
    (("关系", "关联", "其他漏洞", "相似", "类似", "横向", "同族", "除了", "别的",
      "共同点", "同类"),
     "与其他漏洞/威胁事件的关联关系（同组件、同攻击链、同家族横向对比）"),
    (("哪个更严重", "更严重", "哪个危害大", "危害大", "对比", "比较", "差别", "区别"),
     "多漏洞严重性与影响面对比（CVSS/KEV/EPSS/攻击面逐项对比并给结论）"),
    (("影响", "危害", "后果", "波及", "威胁面", "资产", "影响范围", "影响哪些",
      "波及哪些", "受影响"),
     "影响面与危害后果"),
    (("修复", "缓解", "怎么修", "处理", "加固", "补救"), "修复与缓解方案"),
    (("复现", "验证", "poc", "exp"), "验证与复现"),
    # "详细/展开"类泛化追问放最后兜底：与焦点词同现时（"详细说说攻击链"）让位给具体焦点
    (("详细", "展开", "深入", "多说", "多讲", "再讲", "继续说", "继续讲"),
     "全面深入解析（技术机制→利用手法→影响面→修复逐项展开，比上一轮回答更细）"),
)


def _extract_focus(query: str) -> str | None:
    q = (query or "").lower()
    for kws, label in _FOCUS_RULES:
        if any(k in q for k in kws):
            return label
    return None


def _kb_max_date() -> str:
    """库内最新情报日期（真实值注入 prompt，杜绝模型用切片日期瞎猜'库内最新'）。"""
    try:
        db = sqlite3.connect(f"file:{(ROOT / 'data' / 'index.sqlite').as_posix()}?mode=ro",
                             uri=True)
        row = db.execute("SELECT max(date(publish_time)) FROM records "
                         "WHERE publish_time IS NOT NULL AND date(publish_time) IS NOT NULL"
                         ).fetchone()
        db.close()
        return row[0] or ""
    except Exception:
        return ""


def build_messages(r: dict, query: str, history: list | None = None) -> list[dict]:
    """system（专家角色+三段式大纲）+ user（卡片 + 富化增强的文本块 + 问题）。

    富化增强（2026-10-10 深度回答改造）：文章块必须带上 article_enrich 的中文摘要与
    实体五元组（攻击技术/组件/防御）——没有它们，模型只能复述原文切片、退化成语无伦次
    的"标题索引罗列器"。
    多轮上下文（2026-10-15）：history 随请求传来，把最近几轮对话拼进 prompt，
    承接上轮锁定实体而非另起炉灶；r['context'] 里的 inherited_cve/topic 作强化锚点。
    """
    cards = "\n".join(
        f"[卡{i+1}] {c['cve_id']} | 严重度: {c.get('severity') or '-'}(CVSS {c.get('cvss') or '-'}"
        f"{', KEV在野利用' if c.get('kev') else ''}, EPSS {c.get('epss') or '-'})"
        f"| 情报日期: {c.get('publish_time') or '-'} (源: {c.get('source') or '-'}) "
        f"| 组件: {c.get('affected_component') or '-'}"
        f"{(' 版本: ' + str(c['affected_versions'])) if c.get('affected_versions') else ''} "
        f"| 攻击类型: {c.get('attack_type') or '-'}"
        + (f"\n   标准映射: {c['cwe']}" if c.get('cwe') else "")
        + (f"\n   受影响资产(CPE): {c['cpes'][:300]}" if c.get('cpes') else "")
        + (f"\n   可利用性: {c['exploitability_note'][:160]}" if c.get('exploitability_note') else "")
        + f"\n   摘要: {(c.get('summary_zh') or '')[:200]}"
        + (f"\n   修复建议: {(c.get('remediation_zh') or '')[:150]}" if c.get('remediation_zh') else "")
        + (f"\n   英文原描述: {c['description_en'][:600]}" if c.get('description_en') else "")
        for i, c in enumerate(r["cards"])) or "（无）"

    blocks = []
    for i, h in enumerate(r["hits"][:5]):     # 只带 top-5 进生成（配合长切片，prompt 预算可控）
        m = h["meta"]
        head = f"[{i+1}] 《{m.get('title','')}》({m.get('source','')}, {m.get('publish_time','')}) " \
               f"<{m.get('url','')}>"
        parts = [head]
        if m.get("domain") == "article":
            enr = article_enrich(m.get("url", ""))
            if enr.get("summary_zh"):
                parts.append(f"【富化摘要】{enr['summary_zh'][:300]}")
            ent = enr.get("entities") or {}
            ent_line = " | ".join(
                f"{k}: {'、'.join(map(str, v)) if isinstance(v, list) else v}"
                for k, v in ent.items() if v)
            if ent_line:
                parts.append(f"【实体】{ent_line[:300]}")
        parts.append(f"【原文】{h['text'][:2000]}")     # 长切片：给模型足够的展开素材
        blocks.append("\n".join(parts))

    related = "\n".join(
        f"《{a['title']}》({a['source']}, {a['publish_time']}) <{a['url']}>"
        for a in r.get("related", []))
    system = SYSTEM_PROMPT.format(refusal=REFUSAL)
    # 日期锚定 v3（2026-10-16）：v2 仍实测到模型拿单张切片卡日期推断"库内最新"（把
    # 2026-9-17 的卡说成库内最新，实际 10-13）。v3 直接注入库内真实最新日期（已核实
    # 的事实），模型无从猜测；相对日期仍由后端预算换算表，禁止自行算术。
    _today = date.today()
    _kbmax = _kb_max_date()
    system += (f"\n\n【时效设定（严格日期规则）】今天是 {_today.isoformat()}；"
               f"库内情报日期最新为 {_kbmax or '（查询失败，勿猜测）'}——这是已核实的事实，"
               "禁止用检索切片/卡片的日期推断『库内最新日期』，你看到的切片只是相关片段。"
               f"相对日期换算（以此为准，禁止自行推算）："
               f"昨天={(_today - timedelta(days=1)).isoformat()}，"
               f"前天={(_today - timedelta(days=2)).isoformat()}，"
               f"本周={(_today - timedelta(days=6)).isoformat()} 至 {_today.isoformat()}，"
               f"本月={(_today - timedelta(days=29)).isoformat()} 至 {_today.isoformat()}。"
               "日期口径：库内条目的『情报日期/发布日期』即该情报的披露（披露=收录披露日），"
               "回答『某天披露/发布的漏洞』时直接列出该日期的条目，"
               "禁止以『情报日期≠披露日期』为由拒答。"
               "时间类问题的答法：按换算表定位日期范围→在该范围内引用带日期的条目；"
               "若该窗口库内暂无条目，如实说明并给出日期最近的条目。")
    # 多轮上下文：历史快照（最近 3 轮）+ 继承锚点。锚点优先用 search 的继承判定（精确），
    # 兜底用 history 里最近锁定的实体（防御词表漏判：如"他的攻击链"这类人称代词）
    # ——只要历史锁过实体就必须承接，防止被当新主题宏观泛答。
    ctx = r.get("context") or {}
    anchor = ""
    focus_label = _extract_focus(query)   # 追问方向（"它的攻击链路"→ 攻击链路与利用方式）
    if ctx.get("inherited_cve"):
        anchor = (f"用户本轮是承接上一轮的追问，主题锁定为 {ctx['inherited_cve']}；"
                  "必须围绕该漏洞作答，使用其卡片/富化信息展开，不要另找其他主题。")
    elif ctx.get("inherited_topic"):
        anchor = (f"用户本轮是承接上一轮的追问，延续主题「{ctx['inherited_topic']}」；"
                  "必须围绕该主题作答。")
    else:
        for t in (history or [])[::-1]:       # 兜底：历史锁定过实体也要求承接
            if t.get("cve_id"):
                anchor = (f"若用户本轮是承接上一轮的追问（指代词如『它/他/这个漏洞』等），"
                          f"主题锁定为 {t['cve_id']}，必须围绕该漏洞作答，不要跑题；"
                          "若问题明确另指新对象则忽略本段。")
                break
    if anchor:
        # 追问方向聚焦：指代短句的意图藏在词里（"它的攻击链路"→ 攻击链路），显式点出，
        # 防止模型把漏洞全貌复述一遍（用户实测反馈"没针对性，把所有信息说了一遍"）。
        if focus_label:
            anchor += (f" 用户本轮特别关心「{focus_label}」这一方向，回答必须以此为纲深挖"
                       "（技术机制→利用手法→实际影响都围绕该方向展开），"
                       "其他方面从简一句带过；上一轮已答过的内容不要原样重复。")
        else:
            anchor += (" 回答聚焦用户本轮追问的方向本身；不要机械罗列卡片的所有字段，"
                       "上一轮已答过的概览不要原样重复。")
    hist_lines = []
    for t in (history or [])[-3:]:
        role = str(t.get("role") or "")
        content = str(t.get("content") or "")[:200]
        if role == "user":
            hist_lines.append(f"用户: {content}")
        elif role == "assistant":
            asst_focus = f"（助手当时聚焦: {t['cve_id']}）" if t.get("cve_id") else ""
            hist_lines.append(f"助手: {content}{asst_focus}")
    hist_block = "\n".join(hist_lines) or "（无）"

    sim_block = ""
    sim = r.get("similar") or []
    if sim:
        sim_lines = "\n".join(
            f"- {x['cve_id']}（CVSS {x['cvss'] or '-'}{'，KEV 在野' if x['kev'] else ''}）——{x['why']}"
            for x in sim)
        sim_block = f"【关联漏洞（横向推理）】\n{sim_lines}\n\n"
    user = (f"【对话历史】\n{hist_block}\n\n"
            + (f"【本轮承接】\n{anchor}\n\n" if anchor else "")
            + f"【关联漏洞卡片】\n{cards}\n\n"
            f"【检索文本块】\n{chr(10).join(blocks) or '（无）'}\n\n"
            f"【关联分析文章】\n{related or '（无）'}\n\n"
            + sim_block +
            f"【用户问题】\n{query}")
    if r["route"].startswith("sql点查"):
        if r.get("similar"):
            user += ("\n\n【关联推理】若【关联漏洞（横向推理）】非空：在回答末尾附一段【关联漏洞】"
                     "（两三行即可），逐条给出编号与关联原因（同组件/同攻击类型），并点出与本题"
                     "漏洞的共性与差异——这是跨漏洞关联推理的体现，禁止编造清单之外的编号。")
        if len(r.get("cards") or []) > 1:
            user += ("\n\n本题为多 CVE 对比点查：必须逐卡对比 CVSS 评分/严重度/KEV 在野状态/"
                     "EPSS/受影响组件与版本/可利用性，分点或表格清晰呈现差异，最后给出明确结论"
                     "（哪个更严重、为什么、各自处置优先级）。禁止只围绕第一张卡展开而忽略其余。")
        elif focus_label:
            user += (f"\n\n本题为单一 CVE 点查且用户聚焦「{focus_label}」："
                     "【漏洞概览】一句话定位该漏洞（组件/危害/在野状态）即可；"
                     "【核心剖析】必须以上述聚焦方向为唯一主题深入展开，禁止全面铺开罗列漏洞的"
                     "其他信息；【安全防护建议】紧扣该漏洞的具体机制，禁止泛泛通用建议。")
        else:
            user += ("\n\n本题为单一 CVE 点查：【宏观态势综述】一节改为【漏洞概览】"
                     "（一句话定位 + 危害与在野状态 + 标注 CWE 标准映射，取自卡片的“标准映射”行）；"
                     "【核心剖析】聚焦该漏洞的技术机制与利用链路，"
                     "结合英文原描述展开；防护建议必须紧扣该漏洞具体机制，禁止给出与漏洞无关的"
                     "通用安全建议（如泛泛的\"定期审计\"\"加强监控\"）。")
    if r["route"].startswith("组件点查"):
        comp = r.get("component") or "该组件"
        n = r.get("n_component_cves")
        user += (f"\n\n本题为组件级检索（组件：{comp}，库内共收录 {n} 个相关 CVE）。"
                 "按三段组织：①【该组件的漏洞全景】基于【关联漏洞卡片】列出代表性 CVE，"
                 "**必须以表格呈现**（列：CVE 编号、CVSS/严重度、影响版本、危害一句话），"
                 "表格行数与卡片数一致；"
                 "②【分析文章观点】检索文本块中 score≈1.0 的是标题精确命中的分析文章，"
                 "逐篇给出（标题/来源/日期 + 核心观点或攻击手法摘要），"
                 "带【富化摘要】的优先引用；"
                 "③【结论与关注优先级】该组件的风险画像一两句收束。"
                 "禁止说『库内没有相关文章』——标题精确命中即存在。")
    # 时间窗路由（最新情报）：把解析出的窗口与口径写进 user 块（实测 system 块压不住
    # 模型的"情报日期≠披露日期"学究式拒答，2026-10-16 E2E）。窗口被放宽时（用户问的
    # 窗口库内无条目）要求如实说明再给最近条目。
    if r["route"].startswith("最新情报"):
        wr = r.get("window_requested")
        w = r.get("window")
        _t = date.today()
        subj = "、".join(r.get("subject") or [])
        if wr and w:
            user += (f"\n\n本题为时间窗问题（{_t.isoformat()} 起 {w} 天内）。"
                     "卡片的『情报日期』与文章的『发布日期』就是本系统认定的披露日期口径——"
                     f"日期 ≥ {(_t - timedelta(days=w)).isoformat()} 的条目直接作为答案逐条列出"
                     "（编号/标题/危害一句话），禁止纠结『情报日期≠原始披露日期』或据此拒答。"
                     + (f"主题词「{subj}」的中英文说法都算命中（如 RCE=远程代码执行/代码执行），"
                        "命中即列出；" if subj else "")
                     + "按严重度（CVSS/KEV）排序呈现；"
                       "禁止附加用户没有提到的过滤条件（如擅自限定 KEV/在野利用），"
                       "除非窗口内确实零条目，禁止下『未收录/没有』的结论。")
        elif wr and not w:
            user += (f"\n\n本题为时间窗问题，但库内最近 {wr} 天暂无条目（采集有空窗）。"
                     "如实说明这一点，然后给出库内日期最近的条目作为参考（注明其实际日期），"
                     "禁止编造窗口内的条目，也禁止整体拒答。")
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def answer(query: str, model: str = "", show_steps: bool = False, force_cpu: bool = False,
           history: list | None = None) -> dict:
    env = load_dotenv()
    # 主 provider 选择（2026-10-16 用户改定）：DeepSeek 官方为主（新 key 已验证），
    # 硅基流动降为第二档，GLM 兜底（其内容审核会拦安全语料，仅最后手段）。
    sf_key = env.get(PROVIDERS["siliconflow"]["env"], "")
    ds_key = env.get(PROVIDERS["deepseek"]["env"], "")
    glm_key = env.get(PROVIDERS["glm"]["env"], "")
    if model:
        # --model 显式指定：按前缀粗判 provider
        primary_provider = ("deepseek" if (ds_key and model.startswith("deepseek"))
                            else "siliconflow" if (sf_key and model.startswith("deepseek-ai/"))
                            else "glm")
    elif ds_key:
        primary_provider = "deepseek"
        model = PROVIDERS["deepseek"]["model"]
    elif sf_key:
        primary_provider = "siliconflow"
        model = PROVIDERS["siliconflow"]["model"]
    else:
        primary_provider = "glm"
        model = PROVIDERS["glm"]["model"]

    r = search(query, history=history)
    if show_steps:
        print(f"[route] {r['route']}")
        for h in r["hits"][:3]:
            print(f"  {h['score']:.3f} [{h['meta'].get('domain')}] {h['meta'].get('title','')[:50]}")

    # 闲聊/情绪反馈/系统自述 → 直接回复 chat_reply（不调 LLM，不硬搜）。
    # 以 chat_reply 字段为判据：闲聊拦截/系统自述两类路由共用同一出口。
    if r.get("refused") and r.get("chat_reply"):
        return {"answer": r["chat_reply"], "refused": True, "route": r["route"]}

    # 点查未命中 / 检索全空 → 诚实拒答（不调 LLM）
    if r["route"].startswith("sql点查未命中"):
        # 编号从 route 提取：显式 CVE 与"多轮继承改写"两种入口都能取到（继承时 query 本身无编号）
        m = CVE_RE.search(r["route"])
        cid = m.group(0).upper() if m else ""
        return {"answer": f"{REFUSAL}（库内无此记录，可参考 NVD："
                          f"https://nvd.nist.gov/vuln/detail/{cid}）",
                "refused": True, "route": r["route"]}
    if not r["hits"] and not r["cards"]:
        return {"answer": REFUSAL, "refused": True, "route": r["route"]}

    messages = build_messages(r, query, history=history)
    db = sqlite3.connect(f"file:{(ROOT/'data'/'index.sqlite').as_posix()}?mode=ro", uri=True)

    # (provider, model, key) 轮换链：主 provider 优先，余下按质量排序兜底
    # 顺序（2026-10-16 用户改定）：官方 DeepSeek → 硅基流动 → GLM
    chain = []
    for prov in ["deepseek", "siliconflow", "glm"]:
        k = env.get(PROVIDERS[prov]["env"], "")
        if k:
            chain.append({**PROVIDERS[prov], "key": k, "provider": prov})
    # 显式 --model 未命中主链时（如自定义模型名），补一个带该 model 的主 provider 项
    if model and not any(c["provider"] == primary_provider for c in chain):
        k = env.get(PROVIDERS[primary_provider]["env"], "")
        if k:
            chain.insert(0, {**PROVIDERS[primary_provider], "model": model,
                             "key": k, "provider": primary_provider})

    def _generate(messages, c: dict):
        # 深度回答要 40-60s（prompt 6.8k 字符 + 要求 1000-1500 字正文），
        # 抽屉式追问（如"说详细一点"）模型倾向逐条展开，实测 DeepSeek 最长 122.7s；
        # timeout=90 在 90s 整点误杀（2026-10-15 实测 ReadTimeout），放到 180s。
        return call_llm(messages, c["provider"], c["model"], c["key"], timeout=180)

    # GLM 内容审核拦截自愈：检索出的原文块含"不安全内容"敏感词 → 平台 400(1301) 拒收。
    # 等不到是超时，这里是立即拒，混在通用异常里会误判成"免费档坏窗口"（2026-10-15 实测）。
    # DeepSeek 无此问题；此自愈主要兜 GLM 回退档。
    def _is_audit_block(e) -> bool:
        if "HTTPError" not in type(e).__name__:
            return False
        body = getattr(getattr(e, "response", None), "text", "") or str(e)
        return "contentFilter" in body or "1301" in body

    text, used = None, None
    for c in chain:
        try:
            text = _generate(messages, c)
            used = c
            break
        except Exception as e:
            print(f"[qa] {c['model']} {type(e).__name__}，换下家")
            # 内容审核拦截：精简 prompt 再给一次机会（去掉长切片原文，只留卡片+标题+摘要）
            if text is None and _is_audit_block(e):
                try:
                    from search import article_enrich as _enr
                    slim_blocks = []
                    for i, h in enumerate(r["hits"][:3]):
                        mth = h["meta"]
                        enr = _enr(mth.get("url", "")) if mth.get("domain") == "article" else {}
                        slim_blocks.append(
                            f"[{i+1}] 《{mth.get('title','')}》({mth.get('source','')}, "
                            f"{mth.get('publish_time','')})"
                            + (f"\n   摘要: {enr.get('summary_zh','')[:200]}" if enr.get('summary_zh') else ""))
                    slim = ("【关联漏洞卡片】已提供。检索文本块（含敏感细节的原文已省略，仅摘要）：\n"
                            + "\n\n".join(slim_blocks) + f"\n\n【用户问题】\n{query}")
                    slim_messages = [messages[0],
                                     {"role": "user", "content": slim}]
                    text = _generate(slim_messages, c)
                    used = c
                    print(f"[qa] {c['model']} 内容审核，精简 prompt 重试成功")
                    break
                except Exception as e2:
                    print(f"[qa] 精简重试也失败: {type(e2).__name__}")

    if text is None:     # 全部失败：结构化降级（格式化命中+卡片，不再倒原始切片）
        return {"answer": _fallback_answer(r), "refused": False,
                "route": r["route"], "degraded": True}

    bad = fabricate_ids(text, db)
    if bad:              # 拦截 → 重生成一次 → 仍编则剔除
        messages[-1]["content"] += f"\n\n注意：以下 CVE 编号不存在，禁止使用：{', '.join(bad)}"
        print(f"[qa] fabricate_check 拦截 {bad}，重生成")
        try:
            text = _generate(messages, used)
            bad = fabricate_ids(text, db) if used else []
        except Exception:
            pass
        if bad:
            for b in bad:
                text = re.sub(rf"[^。\n]*{re.escape(b)}[^。\n]*[。\n]?", "", text)
            return {"answer": text, "refused": False, "route": r["route"],
                    "fabrications": len(bad), "model": used["model"]}
    db.close()
    return {"answer": text, "refused": False, "route": r["route"],
            "fabrications": 0, "model": used["model"]}


def _fallback_answer(r: dict) -> str:
    """生成服务不可用时的结构化降级：命中列表 + 卡片（带链接分数），不倒原始文本切片。"""
    lines = ["（生成服务暂时不可用——LLM 接口全部失败；以下为结构化检索结果，"
             "可直接阅读原文，接口恢复后自动恢复生成式回答）", ""]
    if r.get("cards"):
        lines.append("【关联漏洞卡片】")
        for c in r["cards"]:
            lines.append(f"- {c['cve_id']} | {(c.get('summary_zh') or '')[:80]} "
                         f"| 组件: {c.get('affected_component') or '-'} | "
                         f"修复: {(c.get('remediation_zh') or '')[:50]}")
        lines.append("")
    lines.append("【检索命中】")
    for h in r.get("hits", [])[:5]:
        m = h["meta"]
        lines.append(f"{h['score']:.3f} 《{m.get('title', '')}》"
                     f"({m.get('source', '')}, {m.get('publish_time', '')}) {m.get('url', '')}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--model", default="", help="覆盖模型（默认 glm-4-flash）")
    ap.add_argument("--show-steps", action="store_true", help="打印检索过程")
    args = ap.parse_args()
    t0 = time.time()
    r = answer(args.query, model=args.model, show_steps=args.show_steps)
    print("\n" + "=" * 40)
    print(r["answer"])
    print("=" * 40)
    print(f"[qa] 拒答={r['refused']} 编造={r.get('fabrications', 0)} "
          f"模型={r.get('model', '-')} 总耗时 {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

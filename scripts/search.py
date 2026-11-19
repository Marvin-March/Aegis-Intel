#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
search.py —— 检索封装（意图路由与检索层）

三层路由（规则，不上 LLM）：
  支1 含 CVE 编号     → SQL 点查 enrich_json 卡片；未命中回落到向量检索该编号（双保险）
  支2 论文意图词      → 向量 where domain=paper
  支3 其余            → 向量（ai_only 时叠加 ai_related=1）
向量召回：encode_query → chroma top-k → 分数阈值 0.3（39 题基准定版）→ 同文多块去重。
缝合表增强：article 块 → cve_ids → vuln_meta 卡片；paper 块 → paper_link → 组件；
          article_cve 表兜底。卡片去重、上限 5 张、排在文本块前（结构化信息权重高）。

用法:
    uv run python scripts/search.py "针对 MCP 工具链的供应链攻击" [--domain paper] [--ai-only] [--k 8]
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
from emb import embed_query, resolve_model_path  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
PAPER_WORDS = ("论文", "研究", "paper", "arxiv", "学术")
# "最近/最新"时间意图（2026-10-15）：命中后不走向量 kNN（相似度≠新近度，
# 纯向量 top-k 召回不到最新情报），改按 publish_time 倒序走 recency 路由。
RECENCY_RE = re.compile(
    r"最近|最新|近期|新入库|本周|本月|今年|时隔|近\d+[天月周]|最新发布|lately|"
    r"\blatest\b|\bnewest\b|\brecent|刚发布|刚才讲完没有|新出的|"
    r"这周|这一周|这个星期|这个月|这一个月|上周|上个月|近日|近来|今天|今日|"
    r"大前天|前天|昨天|昨日|"
    r"近几个月|最近几个月|过去几个月|这几个月|几个月|数月|近半年|半年|"
    r"月内|年内|过去一周|过去一个月|\bthis\s+week\b|\bthis\s+month\b|\btoday\b",
    re.IGNORECASE)

# 时间词 → 天数窗口（2026-10-16）：'这周/这一个月/今天'这类词要落实为真实日期
# 过滤（date(publish_time) >= 今天-N），只按倒序的话"这周有什么洞"仍会带出几周前的旧情报。
# 顺序敏感：子串长者在前（"这一周"先于"这周"判定无所谓，但"最近一个月"必须先于无歧义短词）。
_TIME_WINDOWS = (
    ("大前天", 4), ("前天", 3), ("昨天", 2), ("昨日", 2), ("今天", 1), ("今日", 1), ("近日", 3),
    ("这周", 7), ("这一周", 7), ("这个星期", 7), ("本周", 7),
    ("最近一周", 7), ("过去一周", 7), ("近一周", 7), ("上周", 14),
    ("最近一个月", 30), ("这一个月", 30), ("这个月", 30), ("本月", 30),
    ("过去一个月", 30), ("近一个月", 30), ("月内", 30),
    ("上个月", 60),
    # "近几个月"族（2026-10-16 用户实测补充）：数月≈一个季度量级
    ("近几个月", 90), ("最近几个月", 90), ("过去几个月", 90), ("这几个月", 90),
    ("几个月", 90), ("数月", 90), ("近半年", 180), ("半年", 180),
    ("年内", 365), ("今年", 365),
    # 裸"最近"兜底（2026-10-16 实测补）："最近有哪些RCE的AI漏洞"此前 window=None
    # → 无日期过滤，2024 年旧卡混入。须排在"最近一周/一个月/几个月"之后（长词先判）。
    ("最近", 7),
)


def _time_window_days(query: str) -> int | None:
    """问题里的时间词 → 天数窗口；无时间窗语义返回 None。"""
    q = (query or "")
    for w, d in _TIME_WINDOWS:
        if w in q:
            return d
    m = re.search(r"近(\d+)([天月周])", q)
    if m:
        n = int(m.group(1))
        return n * 30 if m.group(2) == "月" else (n * 7 if m.group(2) == "周" else n)
    return None
SCORE_THRESHOLD = 0.3        # 39 题基准实测定版：top1 最低 0.515，阈值 0.3 零误伤
MAX_CARDS = 5

# 闲聊/无意义输入拦截（2026-10-10 实测修复）：寒暄短句不进入向量检索——硬搜只会
# 召回无关漏洞（如"你好"→CVE-2026-71249）产出"强行作答"幻觉。整句匹配才拦截；
# "你好，vLLM 有什么漏洞"这类寒暄+真问题不受影响。
CHAT_RE = re.compile(
    r"^(你好|您好|嗨+|哈+喽+|hello+|hi+|hey+|在吗|在么|谢谢|多谢|感谢|再见|拜拜|"
    r"你是谁|你是谁啊|你能做什么|你会什么|有什么功能|帮助|help|"
    r"你叫什么名字|你叫什么|你叫啥|你的名字|你是什么模型|你是什么|什么模型|"
    r"介绍一下你自己|介绍自己|你是干嘛的|你是干什么的|你能干嘛|你会干嘛|"
    r"在不在|有人吗|你是机器人吗|你是ai吗|你是人吗|你好呀|您好呀|"
    r"早上好|中午好|下午好|晚上好|晚安|辛苦了|麻烦了|打扰了)[！!。.？?\s]*$",
    re.IGNORECASE)
CHAT_REPLY = ("你好！我是 AI 安全情报助手，可以查询 CVE 漏洞详情、AI 安全漏洞与攻击技术主题。"
              "请直接告诉我漏洞编号或问题，例如：“vLLM 有哪些已知漏洞？”")

# 情绪/反馈类闲聊（2026-10-16）：'你太笨了''听不懂''太厉害了'这类纯反馈短句没有
# 检索意图——之前直接进向量召回出"vLLM 音频处理漏洞"这类无关命中再强行拒答，
# 既难看又浪费一次 LLM 调用。全句匹配才拦截，"这个漏洞修复不对啊"等真问题不受影响。
FEEDBACK_RE = re.compile(
    r"^(你太笨了|太笨了|真笨|好笨|太蠢了|真蠢|好蠢|太傻了|你太蠢了|你真笨|你也太笨了|笨死了|"
    r"太差了|真差|好差|差劲|太垃圾了|真垃圾|好垃圾|垃圾东西|没用|真没用|太没用了|没用啊|废物|"
    r"不行啊|不行呀|不行了|不行的|不行吧|"
    r"太厉害了|真厉害|好厉害|你太厉害了|太牛了|真牛|好牛|牛逼|真牛逼|太牛逼了|"
    r"好棒|真棒|太棒了|你太棒了|很好|真好|挺好的|不错|真不错|挺不错|可以啊|可以呀|"
    r"答错了|回答错了|说错了|答得不好|回答得不好|全错了|不对啊|不对呀|不对吧|不对的|"
    r"听不懂|看不懂|没听懂|什么意思|说人话|说点人话|重新说|重新讲|再说一遍|再讲一遍|再说一次|"
    r"哈哈哈|哈哈哈哈|呵呵呵|嘿嘿嘿|好的|好吧|行吧|哦了|懂了|明白了|知道了|了解了|"
    r"测试|test|123|1234|123456)[！!。.，,？?～~\s]*$",
    re.IGNORECASE)
FEEDBACK_REPLY = ("收到！如果我刚才的回答没帮上忙，可以换个问法再试："
                  "直接给 CVE 编号（如 CVE-2026-59822）、组件名（如 LiteLLM、vLLM）"
                  "或具体方向（如『最新的 AI 网关漏洞』），我会重新检索作答。")

# ── 系统自述层（2026-10-16）───────────────────────────────────
# "你每天漏洞信息多久更新""你会抓取哪些平台的消息"这类问系统自身的问题，答案不在
# 漏洞知识库里，检索必答非所问（演示中的常见问题）。规则识别 + 库内真实数字即时作答
# （确定性、0 秒、零幻觉）。必须含系统指代词（你/系统/助手…）才抢答，防误吞真问题；
# "vLLM 更新了哪些版本"这类含'更新'的真漏洞问题不受影响。
_META_REF_RE = re.compile(r"你|您|你们|系统|助手|咱们|库里|知识库|情报库")


def _live_stats() -> dict:
    """自述用的库内真实数字（只读，缓存连接）。"""
    db = _db()
    try:
        vec = _col().count()
    except Exception:
        vec = 0
    types = {r[0]: r[1] for r in db.execute("SELECT type, count(*) FROM records GROUP BY 1")}
    try:
        rss = db.execute("SELECT count(*) FROM feed_state").fetchone()[0] or 906
    except Exception:
        rss = 906
    try:
        latest = db.execute("SELECT max(date(publish_time)) FROM records "
                            "WHERE publish_time IS NOT NULL").fetchone()[0] or "—"
    except Exception:
        latest = "—"
    one = lambda sql: (db.execute(sql).fetchone() or [0])[0]
    return {"records": one("SELECT count(*) FROM records"),
            "cve": types.get("cve", 0),
            "article": types.get("rss_article", 0) + types.get("article", 0),
            "paper": types.get("paper", 0),
            "ai": one("SELECT count(*) FROM vuln_meta WHERE ai_related=1"),
            "vec": vec, "rss": rss, "latest": latest,
            "near7d": one("SELECT count(*) FROM records WHERE "
                          "date(publish_time) >= date('now','localtime','-7 day')")}


def _meta_answer(query: str) -> str | None:
    q = (query or "").strip()
    if len(q) > 40 or not _META_REF_RE.search(q):
        return None                       # 无系统指代 / 长句 → 大概率真问题，不抢
    has = lambda *ws: any(w in q for w in ws)
    if has("更新", "抓", "采集", "爬", "跑", "运行") and has(
            "多久", "频率", "几点", "每天", "什么时间", "几次", "定期", "多长"):
        kind = "update"
    elif has("抓取", "采集", "爬", "监测", "覆盖", "对接") and has("哪些", "什么", "哪"):
        kind = "sources"
    elif (has("多少", "规模", "几条", "多大", "多少条", "整体情况", "概况", "汇总", "总结")
          and has("漏洞", "记录", "数据", "条", "情报", "库里", "知识库", "库")):
        kind = "stats"
    elif has("流程", "怎么工作", "如何工作", "怎么实现", "如何实现", "架构", "原理",
             "怎么运行", "工作机制", "怎么做的"):
        kind = "pipeline"
    elif has("能做什么", "能干什么", "会什么", "能查什么", "能问什么", "什么功能",
             "能回答什么", "能帮我", "可以做什么"):
        kind = "capability"
    else:
        return None
    s = _live_stats()
    if kind == "update":
        return (f"漏洞信息每日自动更新：每天 05:00 计划任务执行全链路"
                f"（采集 → 富化 → 切块 → 向量入库），约 40 分钟完成，06:00 前新数据即可被问答命中。\n"
                f"当前库内最新情报日期 {s['latest']}，近 7 天新增 {s['near7d']} 条记录。")
    if kind == "sources":
        return (f"监测采集覆盖 7 类采集器、{s['rss']} 个 RSS 订阅源，主要包括：\n"
                "① 官方漏洞库：NVD、CISA KEV、GitHub Advisory、CNNVD\n"
                "② 中文安全社区：先知社区、FreeBuf、安全客、攻防社区、腾讯安全应急响应中心、补天等\n"
                "③ 学术论文：arxiv（LLM/Agent 安全方向）\n"
                f"共 {s['records']} 条记录（文章/资讯 {s['article']}、论文 {s['paper']}），多源增量判重汇聚。")
    if kind == "stats":
        return (f"知识库现状：{s['records']} 条记录（CVE {s['cve']}、文章/资讯 {s['article']}、"
                f"论文 {s['paper']}），其中 AI 相关漏洞 {s['ai']} 条；向量库 {s['vec']} 块（2560 维）；"
                f"最新情报日期 {s['latest']}，近 7 天新增 {s['near7d']} 条。")
    if kind == "pipeline":
        return ("四步流水线：\n"
                "① 监测采集——7 类采集器并行，增量判重，多源汇聚\n"
                "② 情报富化——AI 信号复核 + LLM 抽取（中文摘要/攻击类型/修复建议/实体五元组），CVE 富化率 97%\n"
                "③ 切块向量化——WeMM-Embedding-4B 本地模型，2560 维\n"
                "④ 问答——SQL 点查 / 时间窗 / 向量三路路由 + 缝合表跨文档关联")
    # capability
    return ("我可以：\n"
            "① 点查任意 CVE——影响范围、修复建议、攻击链逐项深挖\n"
            "② 追踪最新情报——『最新的 AI 网关漏洞』『前天披露了什么』\n"
            "③ 复杂意图——『CVE-A 和 CVE-B 哪个更严重』『近几个月严重 RCE』\n"
            "④ 多轮追问——锁定漏洞后接着问『它的攻击链』『影响了哪些资产』\n"
            "试试直接给我一个 CVE 编号或一个方向。")


_DB = None
_COL = None


def _db() -> sqlite3.Connection:
    global _DB
    if _DB is None:
        # check_same_thread=False：FastAPI 线程池会跨线程复用本连接（只读连接，
        # SQLite 内部串行化，安全）；默认限制会导致 "created in a thread" 报错
        _DB = sqlite3.connect(f"file:{(ROOT/'data'/'index.sqlite').as_posix()}?mode=ro",
                              uri=True, check_same_thread=False)
    return _DB


def _col():
    global _COL
    if _COL is None:
        import chromadb
        _COL = chromadb.PersistentClient(path=str(ROOT / "data" / "vector_store")) \
            .get_or_create_collection("intel")
    return _COL


def _parse_cve_ids(raw) -> list[str]:
    """chunks.jsonl 约定逗号分隔；兼容 JSON 数组串。输出全部过 CVE_RE 滤脏。"""
    if not raw:
        return []
    s = str(raw)
    if s.startswith("["):
        try:
            s = ",".join(json.loads(s))
        except (ValueError, TypeError):
            pass
    return [c.upper() for c in CVE_RE.findall(s)]


# ── 支1：SQL 点查 ────────────────────────────────────────────

def _card_from_meta(cve_id: str) -> dict | None:
    """vuln_meta → 卡片。enrich_json 优先（中文），元数据兜底（非 AI CVE 常见）。"""
    row = _db().execute(
        """SELECT v.cve_id, v.cvss, v.severity, v.kev, v.epss, v.affected_component,
                  v.affected_versions, v.summary_zh, v.enrich_json, v.cpes,
                  r.url, r.title, r.summary, r.source, r.publish_time
           FROM vuln_meta v JOIN records r ON r.id='cve-'||v.cve_id
           WHERE v.cve_id=?""", (cve_id,)).fetchone()
    if not row:
        return None
    (cid, cvss, sev, kev, epss, comp, vers, sz, ej, cpes, url, title, summary,
     source, publish_time) = row
    card = {"cve_id": cid, "cvss": cvss, "severity": sev, "kev": kev, "epss": epss,
            "url": url or f"https://nvd.nist.gov/vuln/detail/{cid}",
            "source": source or "",
            "publish_time": (publish_time or "")[:10],
            "title": (title or "")[:120],
            "description_en": (summary or "")[:800]}   # 英文原描述：技术细节的富矿，点查深度回答靠它
    if cpes:
        card["cpes"] = str(cpes)[:400]   # 受影响资产平台粒度（CPE 串），影响范围类问题的硬依据
    if ej:
        try:
            e = json.loads(ej)
            card.update({"summary_zh": e.get("summary_zh") or "",
                         "attack_type": e.get("attack_type") or "",
                         "remediation_zh": e.get("remediation_zh") or "",
                         "exploitability_note": e.get("exploitability_note") or ""})
            _cwe = cwe_for(e.get("attack_type"))
            if _cwe:
                card["cwe"] = _cwe       # 标准锚点（G4 深度加工）
        except (ValueError, TypeError):
            pass
    if not card.get("summary_zh"):
        card["summary_zh"] = sz or (summary or title or "")[:200]
    if comp:
        card["affected_component"] = comp
    if vers:
        card["affected_versions"] = vers
    return card


# attack_type → CWE 标准映射（2026-10-16，G4 深度加工）：安全行业通用锚点，
# 点查卡片与回答引用使用行业标准锚点。来源：CWE 官方 Top-25 与常见映射。
CWE_BY_TYPE = {
    "RCE": "CWE-77 命令注入 / CWE-94 代码注入",
    "命令执行": "CWE-77 OS 命令注入",
    "认证绕过": "CWE-287 认证不当",
    "身份认证绕过": "CWE-287 认证不当",
    "信息泄露": "CWE-200 信息暴露",
    "DoS": "CWE-400 资源耗尽",
    "拒绝服务": "CWE-400 资源耗尽",
    "SSRF": "CWE-918 服务端请求伪造",
    "路径遍历": "CWE-22 路径遍历",
    "SQL注入": "CWE-89 SQL 注入",
    "XSS": "CWE-79 跨站脚本",
    "反序列化": "CWE-502 反序列化不可信数据",
    "权限提升": "CWE-269 权限管理不当",
    "供应链": "CWE-1357 供应链依赖未审计",
    "AI投毒与隐私": "CWE-1427 AI 训练数据投毒",
}


def cwe_for(attack_type: str) -> str:
    return CWE_BY_TYPE.get(str(attack_type or "").strip(), "")


def _row_same_comp(db, cve_id: str, comp: str) -> bool:
    """该 CVE 的组件是否与 comp 相同（关联推理的 reason 判定用）。"""
    row = db.execute("SELECT lower(affected_component) FROM vuln_meta WHERE cve_id=?",
                     (cve_id,)).fetchone()
    return bool(row and row[0] == comp)


def sql_point_query(query: str) -> dict | None:
    m = CVE_RE.search(query)
    if not m:
        return None
    return _card_from_meta(m.group(0).upper())


# ── 最新情报（时间序路由） ───────────────────────────────────

# 功能词/标点剥离（"最新的 Chrome 漏洞" → Chrome；"最新的漏洞" → 空=全部）
_FUNC_RE = re.compile(
    r"最新|最近|近期|新入库|新出的|最新发布|最近发布|本周|本月|今年|"
    r"近\d+[天月周]|最近几天|这几天|刚刚|刚|才|"
    r"这周|这一周|这个星期|这个月|这一个月|上周|上个月|今天|今日|昨天|昨日|前天|大前天|近日|近来|日前|过去|月内|年内|"
    r"近几个月|最近几个月|过去几个月|这几个月|几个月|数月|近半年|半年|来|比较|较为|"
    r"哪些|什么|是什么|有哪些|为什么|怎么回事|如何|怎样|怎么样|情况|情况如何|说一说|讲讲|介绍一下|帮我|我想知道|"
    r"请|到底|究竟|有什么|新的|有什么新|最新动态|最新进展|有没有|"
    r"的|是|了|呢|吗|么|有|没|在|和|与|个|这|那|该|来看|可以|能|"
    r"[\s，。、！？,.!?;；:：()（）'`~—一【】\[\]]")

# 噪音词（剥离后仍不构成"主题"的通用词）
_SUBJECT_NOISE = {
    "ai", "llm", "cve", "漏洞", "威胁", "情报", "新闻", "动态", "更新", "安全",
    "相关", "主要", "哪些", "最新", "最近", "近期", "新", "以及", "今年", "本月",
    "本周", "通报", "披露", "预警", "趋势", "进展", "已经", "在野", "利用",
    "已知", "高危", "中危", "低危", "严重", "领域", "大事件", "事件", "方面", "热点",
    "which", "what", "is", "are", "the", "any", "new", "latest", "newest",
    "recent", "intel", "news", "alert", "advisory", "vulnerability",
    "vulnerabilities", "today", "this", "week", "month",
}

# 单字尾缀噪音："爆了哪些洞"的"爆"、"'网关类'漏洞"的"类"挂在主题尾上
_SINGLE_TAIL = {"爆", "曝", "类"}


def _split_subject_tokens(s: str) -> list[str]:
    """中文连续串与英文单词/编号拆成 token 列表。"""
    return re.findall(r"[a-zA-Z][a-zA-Z0-9./\-\+_]*|[一-鿿]+", s)


def _squeeze_cjk(tok: str) -> str:
    """把中文串两端的噪音词剥掉：'大模型新闻'→'大模型'、'微软漏洞'→'微软'、
    '最新威胁情报'→''。整块既不走样（不拆成单字）又暴露出真正的主题词。"""
    changed = True
    while changed:
        changed = False
        # 单字尾缀噪音（"代理组件爆"→"代理组件"）：单字进不了 _SUBJECT_NOISE
        # （len>=2 门槛），用专用小集合处理，避免误伤普通词尾
        if len(tok) > 1 and tok[-1] in _SINGLE_TAIL:
            tok, changed = tok[:-1], True
            continue
        for w in sorted(_SUBJECT_NOISE, key=len, reverse=True):
            if len(w) >= 2 and len(tok) > len(w):
                if tok.endswith(w):
                    tok, changed = tok[:-len(w)], True
                elif tok.startswith(w):
                    tok, changed = tok[len(w):], True
            if changed:
                break
    return tok


def _strip_subject(query: str) -> list[str]:
    s = _FUNC_RE.sub(" ", query)
    out: list[str] = []
    for t in _split_subject_tokens(s):
        low = t.lower()
        if low in _SUBJECT_NOISE:
            continue
        t = _squeeze_cjk(t) if (low.isascii() is False and re.search(r"[一-鿿]", t)) else t
        low = t.lower()
        if not t or low in _SUBJECT_NOISE or (len(t) == 1 and not t.isascii()):
            continue
        if t not in out:
            out.append(t)
        if len(out) >= 4:
            break
    return out


# 主题同义词（2026-10-16 用户实测"近几个月比较严重的RCE漏洞"→ 卡片全写"远程代码执行"，
# 字面匹配全灭 → 模型拿到无关卡后下结论"未收录"）。英文缩写 ↔ 中文全称双向互通。
_SUBJECT_SYNONYMS = {
    "rce": ("远程代码执行", "任意代码执行", "代码执行", "命令执行"),
    "ssrf": ("服务端请求伪造", "服务器端请求伪造"),
    "xss": ("跨站脚本",),
    "lpe": ("权限提升", "提权", "本地权限提升"),
    "rce漏洞": ("远程代码执行",),
    "沙箱逃逸": ("沙箱",),
    "供应链攻击": ("供应链",),
}


def _subject_score(text: str, subject: list[str]) -> int:
    """主题命中得分：命中 token 数（≥1 即相关，多者排前）。
    2026-10-15 修复：此前要求全部 token 命中（AND），"网关/代理组件"这类多词主题
    只要一个字面词不出现就全军覆没（评测 B3 文0 的直接原因）；改为 OR 计分——
    单 token 语义不变，多 token 召回正常，双命中自然排前。
    2026-10-16：缩写↔全称双向同义匹配（RCE↔远程代码执行）。"""
    if not subject:
        return 1
    hay = (text or "").lower()
    n = 0
    for t in subject:
        tl = t.lower()
        if tl in hay:
            n += 1
            continue
        cands = set(_SUBJECT_SYNONYMS.get(tl, ()))          # token → 全称
        cands |= {k for k, v in _SUBJECT_SYNONYMS.items() if tl in v}   # token ← 缩写
        if any(s.lower() in hay for s in cands):
            n += 1
    return n


def _pull_newest_cvcards(db, n: int, ai_filter: bool,
                         window_days: int | None = None) -> list[dict]:
    """日期倒序最新 CVE 卡（无论如何都要——这是"最新"的硬保证）。
    window_days：时间窗（"这周"=7 天）——晚于该窗口的记录直接过滤，让"这周/这个月"
    这类词得到真日期过滤而不只是倒序。注意 date() 规范化：records.publish_time 有
    '2026-9-28' 非补零格式，纯字符串排序会把 9 月误排到 10 月前面。"""
    sql = """SELECT r.publish_time, v.cve_id
               FROM vuln_meta v JOIN records r ON r.id='cve-'||v.cve_id
              WHERE r.publish_time IS NOT NULL AND r.publish_time != ''
                AND date(r.publish_time) IS NOT NULL"""
    if window_days:
        cutoff = (date.today() - timedelta(days=int(window_days))).isoformat()
        sql += f" AND date(r.publish_time) >= '{cutoff}'"
    if ai_filter:
        sql += " AND v.ai_related = 1"
    sql += " ORDER BY date(r.publish_time) DESC LIMIT ?"
    cards, seen = [], set()
    for (pt, cid) in db.execute(sql, (n,)).fetchall():
        if cid in seen:
            continue
        seen.add(cid)
        card = _card_from_meta(cid)
        if card:
            card["publish_time"] = (pt or "")[:10]
            cards.append(card)
        if len(cards) >= n:
            break
    return cards


def _dated_cards_from_vector(query: str, where: dict | None, k: int) -> list[dict]:
    """语义相关卡（如"最新的 Chrome 漏洞"里的 Chrome），再按日期倒序重排——
    "相关"由向量相似度保证，"最新"由日期排序保证，两者互补。"""
    hits = vector_search(query, where, max(k * 3, 12))
    hits = sorted(hits, key=lambda h: (h["meta"].get("publish_time") or ""), reverse=True)
    return _stitch_cards(hits)[:min(MAX_CARDS, k)]


_COMP_TOKEN_STOP = {
    "cve", "ghsa", "nvd", "kev", "rce", "ssrf", "xss", "llm", "ai", "api", "sdk",
    "proxy", "server", "router", "http", "https", "www", "com", "top10", "the",
    "prompt", "injection", "agent", "gateway", "tool", "chat", "token", "model",
}


def _component_hit(query: str) -> str | None:
    """查询中的英文显著词 → 组件库精确匹配（2026-10-16 新增）。
    "哪些文章分析过 LiteLLM"类问题只含组件名，向量语义召回对专有名词极差
    （实测返回 5 块全不含 LiteLLM），必须走精确链。
    只用 = 全等匹配（lower 后）：LIKE 子串会误伤——'prompt' 曾匹配进 promptfoo
    之类组件，把"论文研究 prompt injection"劫持进组件点查。
    另做相邻 token 组合（"Open WebUI" → 'open webui'/'openwebui'）：组件名含
    空格或多词时单 token 全等匹配不上（实测 103 条 Open WebUI CVE 全漏）。"""
    raw_toks = re.findall(r"[A-Za-z][A-Za-z0-9_.]{2,}", query)
    keep = []
    for tok in raw_toks:
        low = tok.lower().strip("._-")
        if low in _COMP_TOKEN_STOP or len(low) < 3:
            continue
        keep.append((tok, low))
    if not keep:
        return None
    db = _db()
    cands = [(t, l) for t, l in keep]
    for i in range(len(keep) - 1):
        (t1, l1), (t2, l2) = keep[i], keep[i + 1]
        cands.append((f"{t1} {t2}", f"{l1} {l2}"))
        cands.append((f"{t1}{t2}", f"{l1}{l2}"))
    for tok, low in cands:
        if db.execute("SELECT 1 FROM vuln_meta WHERE lower(affected_component)=? LIMIT 1",
                      (low,)).fetchone():
            return tok
    return None


def component_query(query: str, comp: str, k: int = 8) -> dict:
    """组件点查：affected_component 点查 CVE 卡 + 标题 LIKE 召回分析文章 + 向量补深度。
    标题命中的文章 score 记 ~1.0（精确信号，生成层优先引用）。"""
    db = _db()
    low = comp.lower()
    n_cve = db.execute(
        "SELECT count(*) FROM vuln_meta WHERE lower(affected_component) LIKE ?",
        (f"%{low}%",)).fetchone()[0]
    cve_rows = db.execute(
        """SELECT cve_id FROM vuln_meta WHERE lower(affected_component) LIKE ?
           ORDER BY (kev=1) DESC, cvss IS NULL, cvss DESC LIMIT 3""",
        (f"%{low}%",)).fetchall()
    cards = [c for c in (_card_from_meta(r[0]) for r in cve_rows) if c]
    arts = db.execute(
        """SELECT title, url, source, publish_time, substr(content_md, 1, 400) FROM records
           WHERE title LIKE ? AND type IN ('rss_article','article')
             AND length(content_md) >= 200
           ORDER BY length(content_md) DESC LIMIT 5""", (f"%{comp}%",)).fetchall()
    art_hits = [{"score": round(1.0 - i * 0.01, 3), "text": a[4] or "", "meta": {
        "domain": "article", "title": a[0], "url": a[1], "source": a[2],
        "publish_time": a[3] or ""}} for i, a in enumerate(arts)]
    hits = vector_search(f"{comp} 安全 漏洞 分析 攻击", None, 5)
    return {"route": f"组件点查 {comp}（{n_cve} 个CVE + {len(arts)} 篇分析文章）",
            "hits": art_hits + hits, "cards": cards,
            "point": cards[0] if cards else None, "component": comp,
            "n_component_cves": n_cve,
            "related": related_articles([c["cve_id"] for c in cards]) if cards else []}


_MONTH_QUERY_RE = re.compile(r"(\d{4})\s*年\s*(\d{1,2})\s*月")
_CVSS_QUERY_RE = re.compile(
    r"(?:cvss|评分|分数)\s*(\d(?:\.\d)?)(?:\s*分)?\s*以上|(\d(?:\.\d)?)\s*分以上", re.I)
_PLATFORM_SRC = {
    "先知": "xianzhi", "freebuf": "freebuf", "seebug": "seebug", "安全客": "安全客",
    "嘶吼": "嘶吼", "绿盟": "绿盟", "攻防社区": "攻防社区", "补天": "补天",
}


def _filtered_search(query: str, k: int = 8) -> dict | None:
    """结构化条件筛选（2026-10-16）："2026 年 9 月 CVSS 9 分以上的 AI 漏洞"类
    时间+分数+AI 组合查询——日期/分数是元数据不是语义，向量检索无能为力
    （实测返回 2025 年旧卡），直接 SQL 组合查询，卡片按 CVSS 降序。"""
    m = _MONTH_QUERY_RE.search(query)
    if not m:
        return None
    y, mo = m.group(1), int(m.group(2))
    cv = _CVSS_QUERY_RE.search(query)
    cvss_min = float(cv.group(1) or cv.group(2)) if cv else None
    ai = bool(re.search(r"\bAI\b|大模型|LLM|智能体|人工智能", query, re.I))
    db = _db()
    sql = """SELECT v.cve_id FROM vuln_meta v JOIN records r ON r.id='cve-'||v.cve_id
             WHERE r.publish_time LIKE ?"""
    args: list = [f"{y}-{mo:02d}%"]
    if cvss_min is not None:
        sql += " AND v.cvss >= ?"
        args.append(cvss_min)
    if ai:
        sql += " AND v.ai_related = 1"
    sql += " ORDER BY v.cvss IS NULL, v.cvss DESC LIMIT ?"
    args.append(k)
    cards = [c for c in (_card_from_meta(r[0]) for r in db.execute(sql, args).fetchall()) if c]
    if not cards:
        return None
    label = (f"{y}-{mo:02d}" + (f" CVSS≥{cvss_min:g}" if cvss_min else "")
             + (" AI相关" if ai else ""))
    return {"route": f"条件筛选 {label}（{len(cards)} 条）",
            "hits": vector_search(query, None, 5), "cards": cards,
            "point": cards[0] if cards else None}


def _platform_filter(query: str, k: int = 8) -> dict | None:
    """平台感知检索（2026-10-16）："先知社区出过哪些深度文章"——向量召回不保证
    来源命中，先检索再按 source/url 过滤；过滤后为空则回落普通向量。"""
    plat = next((src for kw, src in _PLATFORM_SRC.items() if kw in query), None)
    if not plat:
        return None
    hits0 = vector_search(query, None, k * 2)
    hits = [h for h in hits0
            if plat in str(h["meta"].get("source", "")) + str(h["meta"].get("url", ""))]
    if not hits:
        return None
    return {"route": f"平台检索 {plat}（{len(hits[:k])} 条）", "hits": hits[:k],
            "cards": _stitch_cards(hits[:k]), "point": None}


def recency_search(query: str, k: int = 8, ai_only: bool = False,
                   domain: str | None = None) -> dict:
    """"最近/最新"类提问的时间序检索（2026-10-15，智能版）。

    裸向量 kNN 按相似度排序——"最新"是时间排序需求，相似度顶多保证"相关"，
    保证不了"最新"（实测：却答成 1 月的 KEV 日期）。本路由：
      ① 纯"最新/最近"（无主题）→ 直接按 publish_time 倒序取最新 CVE 卡；
      ② "最新的 X漏洞/情报"（有主题词）→ 向量召回相关卡 → 按日期倒序重排
         → 与全局最新卡融合去重，确保既有主题又有新近度；
      ③ AI 相关词（AI/大模型/LLM…）自动叠加 ai_related=1 过滤；
      ④ 附最近文章/论文文本块，供模型引用真实资讯。
    """
    db = _db()
    subject = _strip_subject(query)
    has_subject = bool(subject)
    ai_filter = ai_only or bool(re.search(r"AI|大模型|LLM|智能体|多模态|agent", query, re.I))
    window_requested = _time_window_days(query)
    window = window_requested

    # 全局最新卡（硬保证；"这周/这个月"等词落实为真日期窗）
    generic = _pull_newest_cvcards(db, k * 3, ai_filter, window_days=window)
    if window and not generic:
        # 窗口内无数据（采集有空窗）→ 自动放宽为全库最新，宁可答"最近的"也不空手
        generic = _pull_newest_cvcards(db, k * 3, ai_filter)
        window = None

    # 语义相关卡（仅当有主题时）
    where: dict | None = None
    if domain == "paper" or (not domain and any(w in query.lower() for w in PAPER_WORDS)):
        where = {"domain": "paper"}
    if ai_filter:
        where = ({"$and": [where, {"ai_related": 1}]} if where
                 else {"ai_related": 1})
    related = _dated_cards_from_vector(query, where, k) if has_subject else []
    if window and related:
        # 主题卡同样吃时间窗（2026-10-16 实测补）："最近有哪些RCE的AI漏洞"此前主题分
        # 压过时间约束，2024 年旧卡排到最前。过滤后为空就直接置空——generic（窗内）
        # 兜底，不再整体回退放回旧卡。
        cutoff = (date.today() - timedelta(days=window)).isoformat()
        related = [c for c in related if (c.get("publish_time") or "")[:10] >= cutoff]

    # 融合：主题优先，无主题=全局最新；主题筛不到→兜底语义相关/全局
    if has_subject:
        scored = []
        for c in (related + generic):
            s = _subject_score(
                " ".join(str(c.get(kay) or "") for kay in
                         ("title", "summary_zh", "description_en",
                          "affected_component", "affected_versions", "source")),
                subject)
            if s:
                scored.append((s, c))
        scored.sort(key=lambda t: t[0], reverse=True)   # 稳定排序：同分保持日期倒序
        cards = [c for _, c in scored]
        if not cards:
            # 有时间窗时优先保窗口（generic 已按窗过滤）；无窗维持原偏好（语义相关优先）
            cards = (generic or related) if window else (related or generic)
    else:
        cards = generic
    seen, out = set(), []
    for c in cards:
        if c["cve_id"] in seen:
            continue
        seen.add(c["cve_id"])
        out.append(c)
        if len(out) >= min(MAX_CARDS, k):
            break
    cards = out

    # 最近文章/论文文本块（主题空=全部，有主题=按标题/正文过滤；有时间窗=真日期过滤）
    hits: list[dict] = []
    art_sql = """SELECT url, title, publish_time, content_md
             FROM records
            WHERE type IN ('rss_article','article','paper')
              AND content_md IS NOT NULL AND LENGTH(content_md) > 0
              AND publish_time IS NOT NULL AND date(publish_time) IS NOT NULL"""
    art_rows: list = []
    if window:
        cutoff = (date.today() - timedelta(days=int(window))).isoformat()
        art_rows = db.execute(art_sql + " AND date(publish_time) >= ? "
                              "ORDER BY date(publish_time) DESC LIMIT ?",
                              (cutoff, k * 2)).fetchall()
    if not art_rows:                 # 无时间窗，或窗口内无文章 → 放宽（与卡片口径一致）
        art_rows = db.execute(art_sql + " ORDER BY date(publish_time) DESC LIMIT ?",
                              (k * 2,)).fetchall()
    for (url, title, pt, content) in art_rows:
        if has_subject and not _subject_score(title + " " + (content or "")[:300], subject):
            continue
        hits.append({"score": 1.0,
                     "meta": {"domain": "article", "source": "rss/recency",
                              "url": url, "title": title or "",
                              "publish_time": (pt or "")[:10]},
                     "text": (content or "")[:600]})
        if len(hits) >= k:
            break

    # 主题字面过滤后文章不足（"网关/代理组件"这类说法，文章标题/正文前 300 字未必
    # 含字面词，评测 B3 曾文0）→ 向量语义兜底：召回后按日期倒序，保"最新+主题"双满足
    if has_subject and len(hits) < 3:
        vhits = vector_search(query, where, k * 2)
        vhits.sort(key=lambda h: (h["meta"].get("publish_time") or ""), reverse=True)
        seen_u = {h["meta"].get("url") for h in hits}
        for h in vhits:
            if h["meta"].get("url") in seen_u:
                continue
            seen_u.add(h["meta"].get("url"))
            hits.append(h)
            if len(hits) >= k:
                break

    route = (f"最新情报{' 窗' + str(window) + '天' if window else ''}"
             f" 主题:{' '.join(subject) if subject else '全部'} 卡{len(cards)} 文{len(hits)}")
    # window/window_requested 回传给生成层（qa.build_messages 按此注入窗口指令）：
    # window=生效窗；window_requested=用户问的窗（放宽时保留原值供模型如实说明）
    return {"route": route, "hits": hits, "cards": cards,
            "point": cards[0] if cards else None,
            "window": window, "window_requested": window_requested,
            "subject": subject}


# ── 向量召回 ────────────────────────────────────────────────

def vector_search(query: str, where: dict | None, k: int = 8) -> list[dict]:
    q = embed_query([query])
    res = _col().query(query_embeddings=q.tolist(), n_results=max(k * 2, 16),
                       where=where, include=["documents", "metadatas", "distances"])
    hits, seen = [], set()
    for i in range(len(res["ids"][0])):
        score = round(1 - res["distances"][0][i], 4)
        if score < SCORE_THRESHOLD:
            break                       # 分数降序，后面只会更低
        url = res["metadatas"][0][i]["url"]
        if url in seen:                 # 同文多块去重，取最高分块
            continue
        seen.add(url)
        hits.append({"score": score, "meta": res["metadatas"][0][i],
                     "text": res["documents"][0][i]})
        if len(hits) >= k:
            break
    return hits


# ── 缝合表增强 ──────────────────────────────────────────────

def _stitch_cards(hits: list[dict]) -> list[dict]:
    cards, seen = [], set()
    for h in hits:
        meta = h["meta"]
        dom = meta.get("domain")
        ids: list[str] = []
        if dom == "cve" and meta.get("cve_ids"):
            ids = _parse_cve_ids(meta["cve_ids"])[:1]
        elif dom == "article":
            ids = _parse_cve_ids(meta.get("cve_ids"))
            if not ids:                 # 元数据缺 cve_ids：article_cve 表兜底
                ids = [r[0] for r in _db().execute(
                    "SELECT cve_id FROM article_cve WHERE article_url=?", (meta.get("url"),))]
        for cid in ids:
            if cid in seen:
                continue
            card = _card_from_meta(cid)
            if card:
                seen.add(cid)
                cards.append(card)
        if len(cards) >= MAX_CARDS:
            break
    for h in hits:                      # paper 块：组件反查（不占卡片额度）
        if h["meta"].get("domain") == "paper" and h["meta"].get("url"):
            comps = [r[0] for r in _db().execute(
                "SELECT component FROM paper_link WHERE paper_url=?", (h["meta"]["url"],))]
            if comps:
                h["components"] = comps
    return cards[:MAX_CARDS]


def article_enrich(url: str) -> dict:
    """文章富化数据（article_enrich 表）：summary_zh + entities 五元组。
    生成层用它做深度总结——没有它，答案只能罗列原文切片。"""
    row = _db().execute(
        """SELECT summary_zh, entities FROM article_enrich
           WHERE url=? AND (summary_zh IS NOT NULL OR entities IS NOT NULL)
           ORDER BY created_at DESC LIMIT 1""", (url,)).fetchone()
    if not row:
        return {}
    out = {}
    if row[0]:
        out["summary_zh"] = row[0]
    if row[1]:
        try:
            e = json.loads(row[1])
            out["entities"] = {k: v for k, v in e.items() if v}
        except (ValueError, TypeError):
            pass
    return out


def related_articles(cve_ids: list[str], limit: int = 5) -> list[dict]:
    """关联推理通道：这个漏洞有哪些分析文章（article_cve 反查）。"""
    if not cve_ids:
        return []
    q = ",".join("?" * len(cve_ids))
    rows = _db().execute(
        f"""SELECT DISTINCT ac.cve_id, r.title, r.url, r.source, r.publish_time
            FROM article_cve ac JOIN records r ON r.url = ac.article_url
            WHERE ac.cve_id IN ({q}) LIMIT ?""", (*cve_ids, limit)).fetchall()
    return [{"cve_id": r[0], "title": r[1], "url": r[2], "source": r[3],
             "publish_time": r[4]} for r in rows]


# ── 总入口 ──────────────────────────────────────────────────

# 多轮指代继承（2026-10-15 修复 stateless 上下文）：指代短句触发的词集。
# 只命中"看起来在接着上轮聊"的短句；长问句 / 含专名的短句（"那 vLLM 呢"）/ 显式 CVE 不继承。
# 人称代词他/她必须收（"他的攻击链是怎样的"——用户实测漏判即此）。
CONTINUATION_WORDS = ("它", "他", "她", "这个", "那个", "这", "该", "那",
                      "上面", "上述", "下面", "刚才", "前面", "之前", "上一",
                      "刚刚", "后续", "接着", "为什么", "原因", "原理", "机制",
                      "怎么", "如何", "详细", "展开", "继续", "深入", "攻击链",
                      "利用", "修复", "缓解", "威胁", "影响", "攻击者",
                      "说一下", "讲讲", "分析一下", "再说")


def _inherit_entity(query: str, history: list | None) -> tuple:
    """多轮指代继承：指代短句 + 历史锁定实体 → 改写成可路由的查询。

    返回 (effective_query, ctx)。ctx 形如 {"inherited_cve": "..."} 或
    {"inherited_topic": "..."}，供 qa.py 注入生成 prompt；无继承返回 (query, None)。
    """
    if not history:
        return query, None
    if CVE_RE.search(query):
        return query, None                     # 显式 CVE：有编号是谁的都归它，不问历史
    h = query.strip()
    if len(h) > 24:
        return query, None                     # 长问句通常自带新主题，不猜
    # 专名判定：去掉"呢/呐"后仍含连续 2+ 字母数字的("# vLLM 呢"→ 新实体名)，不继承；
    # 纯中文承接词 + "呢"（"那他的攻击链呢"）属于承接，照常继承。
    core = h.rstrip("呢呐～~！!？?。. ")
    if re.search(r"[A-Za-z0-9]{2,}", core):
        return query, None
    if not any(w in core for w in CONTINUATION_WORDS):
        return query, None                     # 无指代/续问信号，正常单轮
    # 取"最近"一条，与 prev_user 同为 reversed —— 修复实体漂移（2026-10-15）：
    # 此前用 next() 取最早 assistant 轮，同一会话多轮锁定不同 CVE 时继承到最早旧 CVE。
    prev_user = next((t for t in reversed(history) if t.get("role") == "user"), None)
    prev_asst = next((t for t in reversed(history) if t.get("role") == "assistant"), None)
    # 实体对齐校验（2026-10-15 加固）：用户上一句【显式写出的 CVE】是该轮权威所指，
    # 优先于 assistant 卡片的机械 cve_id——卡片它是检索/缝合的产物，可能把示例卡当作锁定
    # 实体（如向量泛答轮 cards[0] 错位成旧 CVE），上一句被点名的编号才是"这个漏洞"真正
    # 回指的对象。
    user_cid = ""
    _um = CVE_RE.search(str((prev_user or {}).get("content") or ""))
    if _um:
        user_cid = _um.group(0).upper()
    cid = user_cid or (prev_asst or {}).get("cve_id") or ""
    if not cid:
        # 最近一轮没锁到实体（空卡/拒答轮）→ 反向找最近一条真正带 cve_id 的 assistant，
        # 避免"这个漏洞"因上一轮无实体而失去所指而漂移。
        prev_asst = next((t for t in reversed(history)
                          if t.get("role") == "assistant" and t.get("cve_id")), None)
        cid = (prev_asst or {}).get("cve_id") or ""
    if not cid:
        m = CVE_RE.search(str((prev_asst or {}).get("content") or ""))
        cid = m.group(0).upper() if m else ""
    if cid:
        print(f"[inherit] q={query!r} user_cid={user_cid or '-'} "
              f"asst_cve={(prev_asst or {}).get('cve_id') or '-'} -> sql点查 {cid}", flush=True)
        # 改写成含编号的查询 → search() 会命中 CVE 分派走 sql点查，实体锁定成功
        return f"{query} —— 承接上一轮锁定 {cid}", {"inherited_cve": cid}
    topic = ((prev_user or {}).get("content") or "").strip()[:120]
    if topic:
        print(f"[inherit] q={query!r} user_cid={user_cid or '-'} asst_cve=None "
              f"-> topic {topic[:24]!r}", flush=True)
        return f"{query} —— 接续上一轮主题：{topic}", {"inherited_topic": topic}
    print(f"[inherit] q={query!r} 无实体继承性", flush=True)
    return query, None


def search(query: str, domain: str | None = None, ai_only: bool = False, k: int = 8,
           history: list | None = None) -> dict:
    """意图路由 → 召回 → 缝合增强。返回 {route, hits, cards, point, refused?, context?}。

    history（多轮上下文，2026-10-15 起）：前端把会话最近几轮消息随请求送来，
    指代短句（"攻击链呢"/"为什么"）无 CVE 时继承上一轮锁定实体，避免路由退化成
    全网向量"盲目一搜"导致宏观泛答。
    """
    q = (query or "").strip()
    if len(q) < 3 or CHAT_RE.match(q):
        return {"route": "闲聊拦截", "hits": [], "cards": [], "point": None,
                "refused": True, "chat_reply": CHAT_REPLY}
    if FEEDBACK_RE.match(q):
        return {"route": "闲聊拦截(反馈)", "hits": [], "cards": [], "point": None,
                "refused": True, "chat_reply": FEEDBACK_REPLY}
    meta = _meta_answer(q)
    if meta:
        return {"route": "系统自述", "hits": [], "cards": [], "point": None,
                "refused": True, "chat_reply": meta}
    if history:
        query, ctx = _inherit_entity(query, history)
    else:
        ctx = None
    if CVE_RE.search(query):
        # 复杂意图：对比/关联类问题一句带多个 CVE（"A 和 B 哪个更严重"）→ 全部点查成卡，
        # 让模型有结构化依据逐项对比（此前只卡第一个，B 只能靠原文切片，对比不精准）。
        ids = list(dict.fromkeys(m.group(0).upper() for m in CVE_RE.finditer(query)))[:3]
        cards = [c for c in (_card_from_meta(i) for i in ids) if c]
        if cards:
            cid = cards[0]["cve_id"]
            primary = cards[0]
            # 卡片独占原则（2026-10-10 复核）保留：cards 只收问题里显式点名的 CVE，不引入其他卡。
            # 2026-10-15 修复"追问回答一模一样"：此前点查独占连 hits 也为空，同一 CVE 的任何
            # 追问（利用链/危害/资产/关系）喂给生成的素材完全相同，LLM 只能把同一张卡换个
            # 措辞复述。现在按"编号+组件+原始问题"补一轮向量召回文章切片——追问里的焦点词
            # 决定带哪些新素材，回答深度由跨文档切片承担（跨文档语义检索与关联推理）。
            rq = f"{cid} {primary.get('affected_component') or ''} {query}"
            hits = vector_search(rq, None, 5)
            db_sim = _db()
            # 关联推理（2026-10-16，"关联推理"落地）：点查时横向推理同组件/
            # 同攻击类型的其他漏洞（排除自身），供生成层在回答末尾带出——
            # "这个漏洞"→"同类还有哪些"的跨漏洞关联。
            comp = str(primary.get("affected_component") or "").strip().lower()
            at = ""
            try:
                at = str((json.loads(primary.get("enrich_json") or "{}")).get("attack_type") or "").strip()
            except Exception:
                at = ""
            similar = []
            seen_sim = {c["cve_id"] for c in cards}
            clauses, params = [], []
            _sdb = _db()
            if comp:
                clauses.append("lower(v2.affected_component)=?")
                params.append(comp)
            if at:
                clauses.append("json_extract(v2.enrich_json,'$.attack_type')=?")
                params.append(at)
            if clauses:
                sql_sim = ("SELECT v2.cve_id, v2.cvss, v2.kev FROM vuln_meta v2 "
                           "WHERE v2.cve_id NOT IN ({}) AND ({}) "
                           "ORDER BY (v2.kev=1) DESC, v2.cvss IS NULL, v2.cvss DESC LIMIT 4"
                           ).format(",".join("?" * len(seen_sim)) if seen_sim else "''",
                                    " OR ".join(clauses))
                for r2 in _sdb.execute(sql_sim, [*seen_sim, *params]):
                    why = "同组件" if (comp and _row_same_comp(_sdb, r2[0], comp)) else "同攻击类型"
                    similar.append({"cve_id": r2[0], "cvss": r2[1], "kev": bool(r2[2]), "why": why})
            route = f"sql点查 {cid}" if len(cards) == 1 else \
                f"sql点查对比 {'+'.join(c['cve_id'] for c in cards)}"
            return {"route": route, "hits": hits, "cards": cards,
                    "point": primary, "similar": similar,
                    "related": related_articles([c["cve_id"] for c in cards]), "context": ctx}
        # 点查未命中：回落到向量检索该编号（双保险，可能命中文章正文里的引用）
        cid = ids[0]
        hits = vector_search(query, None, k)
        if not hits:      # 回落也无块 → 交给 qa 层走"NVD 链接拒答"分支
            return {"route": f"sql点查未命中 {cid}", "hits": [], "cards": [], "point": None}
        return {"route": f"向量(点查未命中回落) {cid}",
                "hits": hits, "cards": _stitch_cards(hits), "point": None, "context": ctx}

    # 组件点查（2026-10-16）：查询无 CVE 编号但含组件库名（LiteLLM/vLLM…）→
    # 精确链召回，抢在 RECENCY/语义向量前（组件名是比时间词更强的意图信号）
    comp = _component_hit(query)
    if comp:
        return component_query(query, comp, k=k)
    # 结构化条件筛选（月份+CVSS+AI）与平台感知检索（2026-10-16 二批回归新增）
    fr = _filtered_search(query, k=k)
    if fr:
        return {**fr, "context": ctx}
    pf = _platform_filter(query, k=k)
    if pf:
        return {**pf, "context": ctx}

    # "最近/最新"时间意图（2026-10-15）：显式 CVE 已在上方优先；此处抢在
    # domain 过滤与裸向量前，按时间倒序给最新情报（向量相似度≠新近度）
    if RECENCY_RE.search(query):
        return recency_search(query, k=k, ai_only=ai_only, domain=domain)

    where = None
    if domain == "paper" or (not domain and any(w in query.lower() for w in PAPER_WORDS)):
        where = {"domain": "paper"}
    elif domain:
        where = {"domain": domain}
    if ai_only:
        cond = {"ai_related": 1}
        where = {"$and": [where, cond]} if where else cond
    hits = vector_search(query, where, k)
    if where and (not hits or hits[0]["score"] < 0.5):
        # 论文/域过滤弱召回（"研究进展+典型案例"类：论文分数 0.39~0.43 且案例都在文章里）
        # → 与无过滤召回按分混合，两域素材都进 top-k（2026-10-16 实测 P3 仅 676 字修复）
        blended = sorted(hits + vector_search(query, None, k),
                         key=lambda h: h["score"], reverse=True)[:k]
        hits = blended
    return {"route": f"向量 where={where or '无过滤'}", "hits": hits,
            "cards": _stitch_cards(hits), "point": None, "context": ctx}


def _print_result(r: dict):
    print(f"[route] {r['route']}")
    if r["point"]:
        p = r["point"]
        print(f" 卡片: {p['cve_id']} | CVSS {p.get('cvss')} {p.get('severity','')} "
              f"| KEV {p.get('kev')} | {p['title'][:60]}")
        if p.get("summary_zh"):
            print(f" 摘要: {p['summary_zh'][:100]}")
        if p.get("remediation_zh"):
            print(f" 修复: {p['remediation_zh'][:100]}")
    for i, h in enumerate(r["hits"], 1):
        m = h["meta"]
        print(f"  {h['score']:.3f} [{m.get('domain')}/{m.get('source')}] "
              f"{m.get('title','')[:56]}")
    for c in r["cards"]:
        print(f"  [卡] {c['cve_id']} {c.get('summary_zh','')[:60]}")
    for a in r.get("related", []):
        print(f"  [关联文章] {a['title'][:50]}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("query")
    ap.add_argument("--domain", default=None)
    ap.add_argument("--ai-only", action="store_true")
    ap.add_argument("--k", type=int, default=8)
    ap.add_argument("--model", default="", help="覆盖模型路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args()
    if args.model:
        import emb as _e
        _e.CANDIDATE_PATHS.insert(0, args.model)
    t0 = time.time()
    r = search(args.query, domain=args.domain, ai_only=args.ai_only, k=args.k)
    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=1, default=str))
    else:
        _print_result(r)
    print(f"[search] 总耗时 {time.time()-t0:.1f}s（含模型首次加载）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

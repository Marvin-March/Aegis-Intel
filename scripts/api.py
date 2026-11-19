#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api.py —— 问答系统 HTTP API（前端对接契约 + 浏览器自测入口）

启动：uv run uvicorn scripts.api:app --host 0.0.0.0 --port 8000
浏览器体验：http://127.0.0.1:8000/docs （Swagger UI，点 Try it out 直接提问）
前端对接：POST /ask /search /health，字段见各端点注释；CORS 已放开。

模型在服务启动时加载一次（CPU 约 15-45s），之后每条查询 1-3s——所有请求复用
同一份模型与 Chroma 连接，这正是 CLI 模式做不到的（CLI 每次启动都要重载 10GB）。
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import datetime as _dt
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from search import search, related_articles
from qa import answer as qa_answer

_active_run: dict = {}     # 立即采集触发的运行：{run_id, started_at, popen}；结束后由报告文件接管展示

app = FastAPI(title="AI 安全情报问答 API", description="三通道路由：SQL 点查 / 向量检索 / 缝合表关联")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])   # 开发期放开；演示局域网前端可直接对接

_ready_at = time.time()


@app.on_event("startup")
def _warmup():
    """启动即加载嵌入模型（CPU ~60s）：首个请求零冷启动，也彻底关闭惰性加载
    窗口内并发首查触发 torch 段错误的通道（2026-10-15 实测 exit 139）。"""
    try:
        t0 = time.time()
        from search import vector_search
        vector_search("预热", None, 1)
        print(f"[api] 嵌入模型预热完成 {time.time()-t0:.0f}s", flush=True)
    except Exception as e:
        print(f"[api] 预热失败（首个查询会重新加载）: {type(e).__name__}: {e}", flush=True)


class AskReq(BaseModel):
    query: str
    domain: str | None = None          # cve / article / paper（None=自动路由）
    ai_only: bool = False              # 只搜 AI 相关漏洞
    k: int = 8
    with_answer: bool = True           # False=只检索不生成（前端可先展示检索过程再要答案）
    history: list[dict] | None = None  # 多轮上下文：最近几轮 {role, content, cve_id?}


class SearchReq(BaseModel):
    query: str
    domain: str | None = None
    ai_only: bool = False
    k: int = 8
    history: list[dict] | None = None


class CollectRequest(BaseModel):
    mode: str = "manual"


@app.get("/health")
def health():
    from emb import resolve_model_path
    import chromadb
    try:
        n = chromadb.PersistentClient(
            path=str(Path(__file__).resolve().parent.parent / "data" / "vector_store")
        ).get_or_create_collection("intel").count()
    except Exception:
        n = -1
    return {"status": "ok", "model": resolve_model_path(), "store_count": n,
            "uptime_s": round(time.time() - _ready_at)}


@app.get("/api/stats")
def stats():
    """数据看板（Tab 2）：全部真实口径，结构与前端 types/contract.ts 的 StatsResponse 一致
    （前端真实模式请求 /api/stats——注意带 /api 前缀，与 /ask 系列不同）。"""
    import json as _json
    import sqlite3
    base = Path(__file__).resolve().parent.parent

    out: dict = {"vector": {}, "sqlite": {}, "collectors": {}, "bench": {}}
    try:
        v = sqlite3.connect(f"file:{(base/'data'/'vector_store'/'chroma.sqlite3').as_posix()}?mode=ro",
                            uri=True)
        dim_row = v.execute("SELECT dimension FROM collections LIMIT 1").fetchone()
        dom = {r[0]: r[1] for r in v.execute(
            "SELECT string_value, count(*) FROM embedding_metadata WHERE key='domain' GROUP BY 1")}
        v.close()
        out["vector"] = {"count": sum(dom.values()), "dim": dim_row[0] if dim_row else 2560,
                         "metric": "cosine", "model": "WeMM-Embedding-4B",
                         "domains": {"cve": dom.get("cve", 0), "article": dom.get("article", 0),
                                     "paper": dom.get("paper", 0), "daily": dom.get("daily", 0)}}
    except Exception as e:
        out["vector"] = {"count": -1, "dim": 0, "metric": "", "model": f"错误: {e}"[:80],
                         "domains": {"cve": 0, "article": 0, "paper": 0, "daily": 0}}

    db = sqlite3.connect(f"file:{(base/'data'/'index.sqlite').as_posix()}?mode=ro", uri=True)
    ai = db.execute("SELECT count(*) FROM vuln_meta WHERE ai_related=1").fetchone()[0]
    ai_enr = db.execute("""SELECT count(*) FROM vuln_meta WHERE ai_related=1
                           AND enrich_json IS NOT NULL AND enrich_json != ''""").fetchone()[0]
    arts_total = db.execute("""SELECT count(*) FROM records WHERE length(content_md)>=300
                               AND type NOT IN ('cve','advisory','paper')""").fetchone()[0]
    arts_enr = db.execute("""SELECT count(*) FROM article_enrich
                             WHERE summary_zh IS NOT NULL AND summary_zh != ''""").fetchone()[0]
    rss = 906
    tabs = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "feed_state" in tabs:
        rss = db.execute("SELECT count(*) FROM feed_state").fetchone()[0] or rss

    # 看板二期（2026-10-16）：类别占比 / 严重度 / 时间走势 / 平台分布——全部真库口径。
    # severity 列大半为 NULL（实测 UNKNOWN 3527 vs HIGH 16），改按 CVSS 分数分段：
    # ≥9 CRITICAL / ≥7 HIGH / ≥4 MEDIUM / >0 LOW，全库覆盖且口径稳定。
    sev = {r[0]: r[1] for r in db.execute("""
        SELECT CASE WHEN cvss >= 9 THEN 'CRITICAL' WHEN cvss >= 7 THEN 'HIGH'
                    WHEN cvss >= 4 THEN 'MEDIUM' WHEN cvss > 0 THEN 'LOW'
                    ELSE 'UNRATED' END s, count(*)
          FROM vuln_meta GROUP BY 1""")}
    kev = db.execute("SELECT count(*) FROM vuln_meta WHERE kev=1").fetchone()[0]
    cat: dict = {}
    # 类别（2026-10-16 改版）：直接用富化产出的 attack_type 原始值（管线已归一，词表干净：
    # 拒绝服务/认证绕过/RCE/信息泄露/路径遍历/SSRF/反序列化/XSS/权限提升/SQL注入…），
    # 仅并少量同义值——此前关键词粗分桶把"拒绝服务"(424) 等全挤进"其他"，看板没法看。
    _SYN = {"命令执行": "RCE", "拒绝服务": "DoS", "模型供应链投毒": "供应链",
            "数据投毒与隐私": "AI投毒与隐私"}
    for (ej,) in db.execute("""SELECT enrich_json FROM vuln_meta
                               WHERE enrich_json IS NOT NULL AND enrich_json != ''"""):
        try:
            at = str((_json.loads(ej) or {}).get("attack_type") or "").strip()
        except Exception:
            continue
        if not at:
            continue
        at = _SYN.get(at, at)
        cat[at] = cat.get(at, 0) + 1
    # 近 30 天逐日收录（2026-10-16 二次改版）：口径改 crawl_time 入库，与今日速报面板
    # 一致。原 publish_time（披露日）口径下 CVE 披露滞后 + 各源时间格式不齐，
    # 最近两周几乎全 0，与"今日新增 92"自相矛盾。无数据的日子补 0，保证 X 轴连续。
    _today = _dt.date.today()
    days_idx = {(_today - _dt.timedelta(days=i)).isoformat(): 0 for i in range(30)}
    cutoff = min(days_idx)
    for d, c in db.execute(
            """SELECT date(crawl_time), count(*) FROM records
               WHERE crawl_time IS NOT NULL AND date(crawl_time) >= ?
               GROUP BY 1""", (cutoff,)):
        if d in days_idx:
            days_idx[d] = c
    days = [{"day": d, "count": days_idx[d]} for d in sorted(days_idx)]
    art_src = [{"source": str(r[0] or "未知"), "count": r[1]} for r in db.execute(
        """SELECT source, count(*) FROM records
           WHERE type IN ('rss_article','article') GROUP BY 1 ORDER BY 2 DESC LIMIT 20""")]
    pap_src = [{"source": str(r[0] or "未知"), "count": r[1]} for r in db.execute(
        """SELECT source, count(*) FROM records
           WHERE type='paper' GROUP BY 1 ORDER BY 2 DESC LIMIT 10""")]
    out["dist"] = {"attack": cat, "severity": sev, "kev": kev,
                   "days": days, "article_sources": art_src, "paper_sources": pap_src}

    # 今日采集速报（2026-10-16）：按入库时间 crawl_time 口径——"今天抓进来多少"，
    # 与 dist.days（按发布时间）互补。type 中文映射，来源剥 "rss:" 前缀便于展示。
    _TYPE_ZH = {"cve": "CVE 漏洞", "rss_article": "RSS 文章", "paper": "论文",
                "advisory": "安全通告", "article": "深度文章"}
    today_type = {_TYPE_ZH.get(r[0], r[0] or "未知"): r[1] for r in db.execute(
        "SELECT type, count(*) FROM records WHERE date(crawl_time)=date('now','localtime') GROUP BY 1 ORDER BY 2 DESC")}
    today_src = [{"source": str(r[0] or "未知").removeprefix("rss:"), "count": r[1]} for r in db.execute(
        "SELECT source, count(*) FROM records WHERE date(crawl_time)=date('now','localtime') GROUP BY 1 ORDER BY 2 DESC LIMIT 10")]
    _recent_idx = {(_today - _dt.timedelta(days=i)).isoformat(): 0 for i in range(7)}
    for d, c in db.execute(
            """SELECT date(crawl_time), count(*) FROM records
               WHERE date(crawl_time) >= ? GROUP BY 1""", (min(_recent_idx),)):
        if d in _recent_idx:
            _recent_idx[d] = c
    out["today"] = {"date": _today.isoformat(),
                    "total": sum(today_type.values()),
                    "by_type": today_type, "by_source": today_src,
                    "recent_days": [{"day": d, "count": _recent_idx[d]} for d in sorted(_recent_idx)]}

    # 今日重点关注 Top3（2026-10-16，"支撑应急响应决策"）：AI 相关高危中按
    # KEV 在野 > CVSS > EPSS 排序，附一句决策理由——看板从统计数字升级为处置建议。
    _tt = []
    for cid, cvss, kev, epss, sz in db.execute(
            """SELECT v.cve_id, v.cvss, v.kev, v.epss, v.summary_zh
               FROM vuln_meta v WHERE v.ai_related=1
               ORDER BY (v.kev=1) DESC, v.cvss IS NULL, v.cvss DESC, v.epss DESC
               LIMIT 3"""):
        _e = float(epss or 0)
        if kev:
            why = f"KEV 在野利用 + CVSS {cvss} 严重级，应急优先级最高"
        elif _e >= 0.1:
            why = f"CVSS {cvss} 严重级，EPSS {_e:.3f}（被实际利用概率较高）"
        else:
            why = f"CVSS {cvss} 严重级，尚未见在野利用，建议纳入关注"
        _tt.append({"cve_id": cid, "cvss": cvss, "kev": bool(kev),
                    "epss": _e, "summary": (sz or "")[:120], "why": why})
    out["top_threats"] = _tt
    out["sqlite"] = {
        "records": db.execute("SELECT count(*) FROM records").fetchone()[0],
        "ai_vulns": ai,
        "article_cve": db.execute("SELECT count(*) FROM article_cve").fetchone()[0],
        "paper_link": db.execute("SELECT count(*) FROM paper_link").fetchone()[0],
        "affected_component": db.execute("""SELECT count(*) FROM vuln_meta
            WHERE affected_component IS NOT NULL AND affected_component != ''""").fetchone()[0],
        "affected_versions": db.execute("""SELECT count(*) FROM vuln_meta
            WHERE affected_versions IS NOT NULL AND affected_versions != ''""").fetchone()[0],
        # 看板 2026-10-16 改版：CPE 资产覆盖（替换 2% 的 affected_versions 展示）、
        # 近 7 天新增（呼应持续监测）、库内最新情报日期（呼应时间理解）
        "cpes": db.execute("""SELECT count(*) FROM vuln_meta
            WHERE cpes IS NOT NULL AND cpes != '' AND cpes != '[]'""").fetchone()[0],
        "near7d": db.execute("""SELECT count(*) FROM records
            WHERE date(publish_time) IS NOT NULL
              AND date(publish_time) >= date('now','localtime','-7 day')""").fetchone()[0],
        "latest_date": (db.execute("""SELECT max(date(publish_time)) FROM records
            WHERE publish_time IS NOT NULL AND date(publish_time) IS NOT NULL""").fetchone()[0]) or "",
        "export_md": sum(1 for _ in (base/"data"/"export").rglob("*.md"))
                     if (base/"data"/"export").exists() else 0,
        "cve_enrich_rate": round(ai_enr / ai, 3) if ai else 0.0,
        "article_enrich_rate": round(arts_enr / arts_total, 3) if arts_total else 0.0,
    }
    db.close()

    out["collectors"] = {"count": 7, "rss_sources": rss}

    try:
        vd = base / "docs" / "验证结果"
        sm = _json.loads((vd / "smoke_retrieval.json").read_text(encoding="utf-8"))
        lg = _json.loads((vd / "smoke_retrieval_large.json").read_text(encoding="utf-8"))
        vf = _json.loads((vd / "verify_embedding.json").read_text(encoding="utf-8"))
        ts = lg.get("top1_scores") or {}       # 结构: {min, median, max}
        lo, hi = ts.get("min"), ts.get("max")
        out["bench"] = {"smoke": f"{sm.get('hit', '-')}/10",
                        "large": f"{lg.get('hit', '-')}/{lg.get('total', 39)}",
                        "cosine_gate": f"{vf.get('gate', '-')} ≥0.99",
                        "top1_range": f"{lo:.3f}~{hi:.3f}" if lo is not None and hi is not None else "-",
                        "threshold": 0.3, "latency_cpu": "0.5~2.7s"}
    except Exception:
        out["bench"] = {"smoke": "-", "large": "-", "cosine_gate": "-",
                        "top1_range": "-", "threshold": 0.3, "latency_cpu": "-"}
    return out


@app.post("/search")
def do_search(req: SearchReq):
    """检索（不生成）：返回 route（路由判定）、hits（top-k 带分数）、cards（缝合表卡片）。"""
    t0 = time.time()
    r = search(req.query, domain=req.domain, ai_only=req.ai_only, k=req.k,
               history=req.history)
    r["elapsed_s"] = round(time.time() - t0, 2)
    return r


@app.post("/ask")
def do_ask(req: AskReq):
    """问答（检索 + GLM 生成）：返回 route/hits/cards/answer/refused/fabrications。

    answer 引用约定：文本块按 hits 序号 [n] 标注，对应 hits[n-1] 的 url/title。
    前端渲染建议：答案 + 引用链接列表 + 卡片区 + top-k 分数条（演示可视化素材都在响应里）。
    """
    t0 = time.time()
    r = search(req.query, domain=req.domain, ai_only=req.ai_only, k=req.k,
               history=req.history)
    if req.with_answer:
        a = qa_answer(req.query, history=req.history)
        r["answer"] = a.get("answer", "")
        r["refused"] = a.get("refused", False)
        r["fabrications"] = a.get("fabrications", 0)
    r["elapsed_s"] = round(time.time() - t0, 2)
    return r


@app.get("/related")
def get_related(cve_ids: str, limit: int = 5):
    """关联反查：逗号分隔的 CVE 编号 → 分析文章列表。"""
    ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
    return {"articles": related_articles(ids, limit)}


# ── 情报监测 Tab：/api/runs（运行历史）+ /api/collect（立即采集）──
# 契约与前端 types/contract.ts 的 RunRecord/RunsResponse/CollectResponse 一致。

def _pid_alive(pid: str) -> bool:
    try:
        # tasklist 对不存在的 PID 也返回 0（输出"没有运行的任务匹配"），返回码判存活
        # 恒为 True（2026-10-16 实测坑：强杀残留锁在前端永远显示 running）——
        # 改看 /NH CSV 输出行里是否有 "pid" 字段；encoding=gbk 规避读取线程解码崩溃
        r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                           capture_output=True, timeout=10,
                           encoding="gbk", errors="ignore")
        return f'"{pid}"' in (r.stdout or "")
    except Exception:
        return True    # 探测失败按存活处理（宁可不误判，各脚本自身会清陈旧锁）


def _lock_state(base: Path) -> tuple[bool, str, str]:
    """锁文件 = 运行状态真源（Popen 句柄在 DETACHED 子进程上不可靠，2026-10-13 实测）。
    优先级：.collect_full.lock（全链路，含 phase）→ .run_daily.lock（单采集）。
    返回 (running, pid, phase)。"""
    for name in (".collect_full.lock", ".run_daily.lock"):
        lock = base / "data" / name
        if not lock.exists():
            continue
        text = lock.read_text(encoding="utf-8")
        m = re.search(r"pid=(\d+)", text)
        if not m:
            return True, "", ""
        phase = (re.search(r"phase=(\S+)", text) or [None, ""])[1]
        if _pid_alive(m.group(1)):
            return True, m.group(1), phase
    return False, "", ""


def _parse_run_report(path: Path) -> dict | None:
    """解析 data/runs/YYYYMMDD_HHMMSS_mode.md → RunRecord。"""
    m = re.match(r"(\d{8}_\d{6})_(daily|manual|backfill)\.md$", path.name)
    if not m:
        return None
    run_id, mode = m.group(1), m.group(2)
    text = path.read_text(encoding="utf-8", errors="replace")
    started = ""
    tm = re.search(r"时间：([\d\- :]+)", text)
    if tm:
        started = tm.group(1).strip()
    new_records = 0
    nr = re.search(r"新增 ([\-\d]+)", text)
    if nr:
        new_records = int(nr.group(1))
    duration, ok, seen = 0.0, True, 0
    for row in re.findall(r"^\| \S+ \| ([✅❌]) \| ([\d.]+) \|", text, re.M):
        seen += 1
        duration += float(row[1])
        if row[0] == "❌":
            ok = False
    return {"run_id": run_id, "mode": mode, "started_at": started,
            "duration_s": round(duration, 1), "new_records": new_records,
            "status": "ok" if ok else "failed"}


@app.get("/api/vulns")
def vulns(severity: str = "", attack: str = "", limit: int = 30):
    """看板下钻（2026-10-16）：严重度 chip / 攻击类别条点击后列出对应漏洞卡。
    severity 用 CVSS 分段（与 /api/stats dist.severity 同口径）；attack 精确匹配
    enrich_json 里的 attack_type 展示名（DoS→拒绝服务 映射回库存中文原词）。"""
    import json as _json
    import sqlite3
    base = Path(__file__).resolve().parent.parent
    db = sqlite3.connect(f"file:{(base/'data'/'index.sqlite').as_posix()}?mode=ro", uri=True)
    where, params = [], []
    band = {"CRITICAL": (9, 1e9), "HIGH": (7, 9), "MEDIUM": (4, 7), "LOW": (0.0001, 4)}
    if severity:
        lo, hi = band.get(severity.upper(), (None, None))
        if lo is not None:
            where.append("v.cvss >= ? AND v.cvss < ?")
            params += [lo, hi]
        elif severity.upper() == "UNRATED":
            where.append("(v.cvss IS NULL OR v.cvss = 0)")
    if attack:
        stored = {"DoS": "拒绝服务"}.get(attack, attack)
        where.append('v.enrich_json LIKE ?')
        params.append(f'%"attack_type": "{stored}"%')
    wsql = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.execute(f"SELECT count(*) FROM vuln_meta v{wsql}", params).fetchone()[0]
    rows = db.execute(
        f"""SELECT v.cve_id, v.cvss, v.severity, v.kev, v.summary_zh, v.enrich_json,
                   r.publish_time
            FROM vuln_meta v LEFT JOIN records r ON r.id='cve-'||v.cve_id{wsql}
            ORDER BY date(r.publish_time) DESC LIMIT ?""",
        params + [max(1, min(limit, 100))]).fetchall()
    db.close()
    out = []
    for cid, cvss, sev2, kev, sz, ej, pt in rows:
        at = ""
        try:
            at = str((_json.loads(ej) or {}).get("attack_type") or "")
        except Exception:
            pass
        out.append({"cve_id": cid, "cvss": cvss, "severity": sev2,
                    "kev": bool(kev) if kev is not None else False,
                    "publish_time": (pt or "")[:10], "attack_type": at,
                    "summary_zh": (sz or "")[:120],
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}"})
    return {"total": total, "vulns": out}


@app.get("/api/runs")
def runs():
    """采集运行历史：data/runs/*.md 报告 + 正在运行的采集任务（锁文件判定）。"""
    base = Path(__file__).resolve().parent.parent
    recs = []
    for p in sorted((base / "data" / "runs").glob("*.md"), reverse=True):
        r = _parse_run_report(p)
        if r:
            recs.append(r)
    running, pid, phase = _lock_state(base)
    if running:
        recs.insert(0, {"run_id": _active_run.get("run_id", datetime.now().strftime("%Y%m%d_%H%M%S")),
                        "mode": "manual",
                        "started_at": _active_run.get("started_at", "-"),
                        "duration_s": round(time.time() - _active_run.get("ts", time.time())),
                        "new_records": 0, "status": "running",
                        "phase": phase or "采集中"})   # 全链阶段：采集/富化/切块/向量
    return {"runs": recs[:20]}


@app.post("/api/collect")
def collect(req: CollectRequest):
    """立即采集按钮：后台拉起 run_daily --mode manual（不阻塞本请求）。
    运行状态以 run_daily 锁文件为准：已在跑 → started=False；陈旧锁先清理再起。"""
    base = Path(__file__).resolve().parent.parent
    running, pid, _ = _lock_state(base)
    if running:
        return {"run_id": _active_run.get("run_id", f"locked-{pid}"), "started": False}
    for name in (".collect_full.lock", ".run_daily.lock", ".enrich_daily.lock"):
        p = base / "data" / name
        if p.exists():
            p.unlink(missing_ok=True)     # 陈旧锁（pid 已死）：各脚本自身也会清，这里先清
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    log = base / "data" / "runs" / "logs" / f"api_collect_{run_id}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    with open(log, "w", encoding="utf-8") as f:
        # 全链路驱动：采集 → 富化 → 切块 → 向量增量（跑完新数据即可被问答命中）
        subprocess.Popen(
            [sys.executable, "-u", "scripts/collect_full.py"],
            cwd=str(base), stdout=f, stderr=subprocess.STDOUT, env=env)
    _active_run.update({"run_id": run_id, "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "ts": time.time()})
    return {"run_id": run_id, "started": True}


# 前端静态托管（必须放在所有 API 路由注册之后，否则 mount("/") 会吞掉 /ask /health 等端点）：
# 队友 build 产物放 frontend/dist/ 后，浏览器打开 http://localhost:8000 即是完整系统
_frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(_frontend_dist), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

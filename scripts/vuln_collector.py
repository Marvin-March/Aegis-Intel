#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏洞线 + 论文线采集器 —— 阶段二 B1 的确定性富化在这里同步完成

五个源，一个脚本（都是官方 API/开放数据，无反爬）：
  nvd    NVD API 2.0 增量拉取（按 lastModified），结构化 CVE：描述/CVSS/CPE/引用
  kev    CISA KEV 在野利用清单（一个 JSON 全量）
  epss   FIRST EPSS 利用概率（每日全量 CSV.gz，回填到 vuln_meta）
  osv    OSV.dev 按 AI 生态包名查询（langchain/mlflow/vllm/...，AI 供应链漏洞主源）
  arxiv  arXiv 论文（LLM security 等查询词，type=paper）

产出：
  records 统一记录（type=cve/advisory/paper）进同一个 SQLite+JSONL
  vuln_meta 结构化富化表：cve_id, cvss, severity, kev, epss, cpes, ai_related, matched
  ——图谱/问答后续直接吃 vuln_meta，这就是"确定性富化"的第一层。

用法：
    uv run python scripts/vuln_collector.py --source all --lookback 30
    uv run python scripts/vuln_collector.py --source nvd --lookback 2      # 试跑
    uv run python scripts/vuln_collector.py --source osv --max-packages 5  # 试跑
增量：nvd 用 data/state.json 记录上次 lastModified；kev/epss/osv 靠判重。
注意：cvelistV5（GitHub 提交通道，零延迟）留到 A4 上 Actions 时接，本地 NVD 覆盖同样数据（延迟数小时）。
"""

import argparse
import csv
import gzip
import io
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

from xianzhi_crawler import Store, UA, now_iso

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OSV_API = "https://api.osv.dev/v1/query"
ARXIV_API = "http://export.arxiv.org/api/query"

AI_RE = re.compile(
    r"\b(langchain|langgraph|llama|mlflow|vllm|pytorch|torch|tensorflow|transformers|"
    r"huggingface|ollama|comfyui|open-webui|gradio|dify|litellm|chatgpt|openai|"
    r"anthropic|claude|gemini|copilot|whisper|stable-diffusion|invokeai|automatic1111|"
    r"text-generation-webui|jupyter-ai|llm|gpt|ai)\b|大模型|智能体|人工智能|提示词",
    re.I)


def sess_with(cfg):
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    if cfg.get("proxy"):
        s.proxies = {"http": cfg["proxy"], "https": cfg["proxy"]}
    return s


def match_ai(text: str):
    """词边界正则匹配 AI 组件/术语，避免 'Dubai' 这类子串误报；中文词直接子串匹配。"""
    hits = sorted({m.group(0).lower().strip() for m in AI_RE.finditer(text or "") if m.group(0).strip()})
    return hits


# ---------- NVD ----------

def nvd_cpes(cve_json):
    out = []
    for cfg_ in cve_json.get("configurations", []):
        for node in cfg_.get("nodes", []):
            for m in node.get("cpeMatch", []):
                out.append(m.get("criteria", ""))
    return out


def nvd_records(cve_json):
    cid = cve_json["id"]
    descs = {d["lang"]: d["value"] for d in cve_json.get("descriptions", [])}
    desc = descs.get("en") or next(iter(descs.values()), "")
    metrics = cve_json.get("metrics", {})
    v31 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    score = v31.get("cvssData", {}).get("baseScore")
    severity = v31.get("cvssData", {}).get("baseSeverity", "")
    cpes = nvd_cpes(cve_json)
    refs = [r.get("url", "") for r in cve_json.get("references", [])][:10]
    # 写入端质量门④：AI 信号分级——CPE 组件名命中=强（可短路 LLM），仅描述词命中=弱（必须 LLM 复核）
    strong = match_ai(" ".join(cpes))
    weak = [h for h in match_ai(desc) if h not in strong]
    matched = strong + weak
    ai_signal = "strong" if strong else ("weak" if weak else "none")
    rec = {
        "id": "cve-" + cid,
        "source": "nvd",
        "type": "cve",
        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "title": f"{cid}{' [' + severity + ']' if severity else ''}: {desc[:90]}",
        "summary": desc[:1200],
        "publish_time": (cve_json.get("published") or "")[:16].replace("T", " "),
        "tags": ["cve", "nvd"] + ([f"AI:{matched[0]}"] if matched else []) + ([f"CVSS:{severity}"] if severity else []),
        "crawl_time": now_iso(),
        "content_md": (f"{desc}\n\n- CVSS: {score} ({severity})\n"
                       + "\n".join(f"- CPE: {c}" for c in cpes[:8])
                       + "\n" + "\n".join(f"- Ref: {u}" for u in refs)),
    }
    meta = {"cve_id": cid, "cvss": score, "severity": severity, "kev": 0, "epss": None,
            "cpes": json.dumps(cpes, ensure_ascii=False), "ai_related": 1 if matched else 0,
            "matched": json.dumps(matched, ensure_ascii=False),
            "ai_signal": ai_signal, "updated_at": now_iso()}
    return rec, meta


def run_nvd(cfg, store, lookback_days):
    state_p = Path(cfg["out_dir"]) / "state.json"
    state = json.loads(state_p.read_text()) if state_p.exists() else {}
    end = datetime.now(timezone.utc)
    start = datetime.fromisoformat(state["nvd_last_mod"]) if state.get("nvd_last_mod") \
        else end - timedelta(days=lookback_days)
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    key = cfg.get("nvd_api_key") or ""
    hdr = {"apiKey": key} if key else {}
    delay = 1.2 if key else 7.0        # 无 key 限 5 请求/30秒
    s = sess_with(cfg)

    # T5 页级断点：窗口存在且未完成 → 从断点页续传（含 1 小时重叠窗防漏）
    start_idx, total = 0, None
    win = state.get("nvd_window")
    if win and win.get("end") == fmt(end):
        start = datetime.fromisoformat(win["start"])
        start_idx = int(win.get("next_index", 0))
        print(f"[nvd] 从断点续传：startIndex={start_idx}")
    else:
        state.pop("nvd_window", None)

    n_new, n_meta = 0, 0

    def save_state(next_idx):
        state["nvd_window"] = {"start": fmt(start), "end": fmt(end), "next_index": next_idx}
        state_p.parent.mkdir(parents=True, exist_ok=True)
        state_p.write_text(json.dumps(state))

    while True:
        url = (f"{NVD_API}?lastModStartDate={fmt(start)}&lastModEndDate={fmt(end)}"
               f"&startIndex={start_idx}&resultsPerPage=2000")
        data = None
        for attempt in range(4):   # SSL EOF/超时是常态（NVD 在境外），指数退避重试
            try:
                r = s.get(url, headers=hdr, timeout=30)
                if r.status_code == 200:
                    data = r.json()
                    break
                print(f"[nvd] HTTP {r.status_code}，重试 {attempt + 1}/4")
            except requests.RequestException as e:
                print(f"[nvd] {type(e).__name__}，重试 {attempt + 1}/4")
            time.sleep(5 * (attempt + 1))
        if data is None:
            print("[nvd] 连续失败，本轮停止（断点已存，下次从断点页续传）")
            save_state(start_idx)
            return
        total = data.get("totalResults", 0)
        for item in data.get("vulnerabilities", []):
            rec, meta = nvd_records(item["cve"])
            if not store.seen(rec["url"]):
                store.upsert(rec, "listed")
                n_new += 1
            store.db.execute("""INSERT INTO vuln_meta(cve_id,cvss,severity,kev,epss,cpes,ai_related,matched,ai_signal,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET cvss=excluded.cvss, severity=excluded.severity,
                cpes=excluded.cpes, ai_related=excluded.ai_related, matched=excluded.matched,
                ai_signal=excluded.ai_signal, updated_at=excluded.updated_at""",
                (meta["cve_id"], meta["cvss"], meta["severity"], meta["kev"], meta["epss"],
                 meta["cpes"], meta["ai_related"], meta["matched"], meta["ai_signal"],
                 meta["updated_at"]))
            n_meta += 1
        store.db.commit()
        start_idx += data.get("resultsPerPage", 0)
        save_state(start_idx)          # T5：每页推进断点，中断后不重拉整窗
        print(f"[nvd] 已处理 {min(start_idx, total)}/{total}")
        if start_idx >= total or not data.get("vulnerabilities"):
            break
        time.sleep(delay)
    state.pop("nvd_window", None)      # 窗口完成：清除断点，推进水位
    state["nvd_last_mod"] = fmt(end)
    state_p.parent.mkdir(parents=True, exist_ok=True)
    state_p.write_text(json.dumps(state))
    print(f"[nvd] 新记录 {n_new}，vuln_meta {n_meta} 条")


# ---------- KEV ----------

def run_kev(cfg, store):
    s = sess_with(cfg)
    r = s.get(KEV_URL, timeout=30)
    data = r.json()
    n_new, n_kev = 0, 0
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID", "")
        if not cid:
            continue
        n_kev += 1
        store.db.execute("UPDATE vuln_meta SET kev=1, updated_at=? WHERE cve_id=?", (now_iso(), cid))
        rec_url = f"https://nvd.nist.gov/vuln/detail/{cid}"
        if not store.seen(rec_url):
            rec = {
                "id": "cve-" + cid, "source": "kev", "type": "cve",
                "url": rec_url,
                "title": f"{cid} [KEV在野利用]: {v.get('vulnerabilityName', '')}",
                "summary": v.get("shortDescription", ""),
                "publish_time": v.get("dateAdded", ""),
                "tags": ["cve", "kev", f"KEV:{v.get('vendorProject', '')}/{v.get('product', '')}"],
                "crawl_time": now_iso(),
                "content_md": (f"{v.get('shortDescription', '')}\n\n- 勒索软件关联: "
                               f"{v.get('knownRansomwareCampaignUse', 'Unknown')}\n- 处置期限: "
                               f"{v.get('dueDate', '')}\n- 通告: {v.get('notes', '')}"),
            }
            store.upsert(rec, "listed")
            store.db.execute("""INSERT OR IGNORE INTO vuln_meta(cve_id,kev,updated_at) VALUES(?,1,?)""", (cid, now_iso()))
            n_new += 1
    store.db.commit()
    print(f"[kev] 清单 {n_kev} 条，新增记录 {n_new}，vuln_meta.kev 已标记")


# ---------- EPSS ----------

def parse_epss_csv(text: str) -> list:
    """解析 EPSS 全量 CSV（首行注释+表头），返回 [(cve, epss)]。与 run_epss 分离便于测试。"""
    rows = [ln.split(",") for ln in text.splitlines() if ln and not ln.startswith("#")]
    return [(r[0], r[1]) for r in rows[1:] if len(r) >= 2]


def run_epss(cfg, store):
    s = sess_with(cfg)
    r = s.get(EPSS_URL, timeout=60)
    gz = gzip.decompress(r.content).decode("utf-8", errors="ignore")
    rows = parse_epss_csv(gz)
    n = 0
    for cve_id, score in rows:
        store.db.execute("UPDATE vuln_meta SET epss=? WHERE cve_id=?", (score, cve_id))
        n += 1
    store.db.commit()
    print(f"[epss] 全量 {n} 条分数已回填 vuln_meta（只有已在库的 CVE 会被更新）")


# ---------- OSV ----------

def run_osv(cfg, store, max_packages):
    s = sess_with(cfg)
    pkgs = cfg.get("osv_packages", [])
    if max_packages:
        pkgs = pkgs[:max_packages]
    n_new = 0
    for p in pkgs:
        eco = "PyPI"
        name = p
        if ":" in p:
            eco, name = p.split(":", 1)
        try:
            r = s.post(OSV_API, json={"package": {"name": name, "ecosystem": eco}}, timeout=20)
            vulns = r.json().get("vulns", [])
        except Exception as e:
            print(f"  [skip] osv {name}: {type(e).__name__}")
            continue
        for v in vulns:
            vid = v.get("id", "")
            link = f"https://osv.dev/vulnerability/{vid}"
            if store.seen(link):
                continue
            summary = v.get("summary") or (v.get("details") or "")[:300]
            aliases = [a for a in v.get("aliases", []) if a.startswith("CVE")]
            is_cve = vid.startswith("CVE")
            rec = {
                "id": ("cve-" if is_cve else "advisory-") + vid,
                "source": "osv", "type": "cve" if is_cve else "advisory",
                "url": link,
                "title": f"{vid}: {summary[:90]}",
                "summary": (v.get("details") or summary)[:1200],
                "publish_time": (v.get("modified") or v.get("published") or "")[:16].replace("T", " "),
                "tags": ["osv", eco, name] + [f"CVE:{a}" for a in aliases[:3]]
                        + [f"AI:{name}"],
                "crawl_time": now_iso(),
                "content_md": f"{v.get('details') or summary}\n\n- 包: {eco}/{name}\n- 关联CVE: {', '.join(aliases) or '-'}",
            }
            store.upsert(rec, "listed")
            cve_id = aliases[0] if aliases else vid
            store.db.execute("""INSERT OR IGNORE INTO vuln_meta(cve_id,ai_related,matched,updated_at) VALUES(?,1,?,?)""",
                             (cve_id, json.dumps([f"{eco}/{name}"]), now_iso()))
            n_new += 1
        time.sleep(0.3)
    store.db.commit()
    print(f"[osv] 查询 {len(pkgs)} 个 AI 包，新增 {n_new} 条")


# ---------- arXiv ----------

def run_arxiv(cfg, store, max_papers):
    s = sess_with(cfg)
    n_new = 0
    for q in cfg.get("arxiv_queries", []):
        d = None
        for attempt in range(3):   # arXiv API 偶发 502/限流，重试两次
            try:
                r = s.get(ARXIV_API, params={
                    "search_query": f'all:"{q}"', "sortBy": "submittedDate",
                    "sortOrder": "descending", "max_results": max_papers},
                    timeout=30, headers={"User-Agent": "aegis-intel-collector/0.1 (research)"})
                if r.status_code == 200 and r.content:
                    d = feedparser.parse(r.content)
                    break
                print(f"  [retry] arxiv '{q}': HTTP {r.status_code}")
            except Exception as e:
                print(f"  [retry] arxiv '{q}': {type(e).__name__}")
            time.sleep(5)
        if d is None:
            continue
        for e in d.entries:
            link = e.get("link", "")
            if not link or store.seen(link):
                continue
            rec = {
                "id": "arxiv-" + hashlibslug(link),
                "source": "arxiv", "type": "paper",
                "url": link,
                "title": re.sub(r"\s+", " ", e.get("title", "")).strip(),
                "summary": re.sub(r"\s+", " ", e.get("summary", "")).strip()[:1200],
                "publish_time": (e.get("published") or "")[:16].replace("T", " "),
                "tags": ["paper", "arxiv", q],
                "crawl_time": now_iso(),
                "content_md": "",
            }
            store.upsert(rec, "listed")
            n_new += 1
        time.sleep(3)   # arXiv 要求间隔
    print(f"[arxiv] 查询 {len(cfg.get('arxiv_queries', []))} 个主题，新增 {n_new} 篇")


def hashlibslug(link: str) -> str:
    import hashlib
    m = re.search(r"abs/([^v]+v\d+)", link)
    return (m.group(1) if m else hashlib.sha1(link.encode()).hexdigest()[:16]).replace("/", "").replace(".", "-")


# ---------- GitHub Advisory ----------

GH_ADV_API = "https://api.github.com/advisories"
GH_PROXY = ""   # GitHub API 默认直连；国内网络需代理时在 config.vuln.proxy 配置


def run_github_advisory(cfg, store):
    """GitHub Security Advisory：AI 包精确受影响版本区间（>=x, <y）——富化的独有素材。"""
    s = sess_with({"proxy": cfg.get("proxy", GH_PROXY)})
    token = cfg.get("github_token") or ""
    hdr = {"Accept": "application/vnd.github+json"}
    if token:
        hdr["Authorization"] = f"Bearer {token}"
    pkgs = cfg.get("osv_packages", [])
    n_new, n_meta = 0, 0
    for pkg in [p.split(":")[-1] for p in pkgs if not p.startswith("npm:")]:
        try:
            r = s.get(GH_ADV_API, params={"ecosystem": "pip", "affects": pkg,
                                          "per_page": 100}, headers=hdr, timeout=25)
            if r.status_code != 200:
                print(f"  [gha] {pkg}: HTTP {r.status_code}")
                continue
            advisories = r.json()
        except requests.RequestException as e:
            print(f"  [gha] {pkg}: {type(e).__name__}")
            continue
        for adv in advisories:
            ghsa = adv.get("ghsa_id", "")
            cve = adv.get("cve_id") or ""
            url = f"https://github.com/advisories/{ghsa}"
            if store.seen(url):
                continue
            # 版本区间（GH 独有）：取第一个 vulnerable range
            vers = adv.get("vulnerabilities") or []
            vr = vers[0].get("vulnerable_version_range", "") if vers else ""
            patched = vers[0].get("patched_versions", "") if vers else ""
            sev = (adv.get("severity") or "").lower()
            rec_id = ("cve-" + cve) if cve else "ghsa-" + ghsa
            # 合并语义：同 CVE 已在库（NVD 先入）→ 追加"精确版本区间"节，不建新行
            existing = store.db.execute("SELECT content_md FROM records WHERE id=?", (rec_id,)).fetchone()
            if existing and cve:
                if "精确版本区间" not in (existing[0] or ""):
                    add = (f"\n\n### 精确版本区间（GitHub Advisory）\n"
                           f"- 包: pip/{pkg}\n- 受影响: {vr}\n- 修复版本: {patched}\n- GHSA: {ghsa}")
                    store.db.execute("UPDATE records SET content_md=content_md||?, crawl_time=? WHERE id=?",
                                     (add, now_iso(), rec_id))
                store.db.execute("""INSERT OR IGNORE INTO vuln_meta(cve_id,severity,ai_related,matched,ai_signal,updated_at)
                    VALUES(?,?,1,?, 'strong', ?)""",
                    (cve, sev, json.dumps([f"pip/{pkg}"]), now_iso()))
                n_meta += 1
                continue
            rec = {
                "id": rec_id,
                "source": "github_advisory",
                "type": "cve" if cve else "advisory",
                "url": url,
                "title": f"{ghsa}: {adv.get('summary', '')[:90]}",
                "summary": (adv.get("description") or "")[:1200],
                "publish_time": (adv.get("published_at") or "")[:16].replace("T", " "),
                "tags": ["ghsa", "pip", pkg, f"AI:{pkg}",
                         f"修复:{patched}"] if patched else ["ghsa", "pip", pkg, f"AI:{pkg}"],
                "crawl_time": now_iso(),
                "content_md": (f"{adv.get('summary', '')}\n\n{adv.get('description', '')}\n\n"
                               f"- 包: pip/{pkg}\n- 受影响版本: {vr}\n- 修复版本: {patched}\n"
                               + (f"- CVE: {cve}\n" if cve else "")
                               + f"- 严重度: {adv.get('severity', '')}"),
            }
            store.upsert(rec, "listed")
            key = cve or ghsa
            store.db.execute("""INSERT OR IGNORE INTO vuln_meta(cve_id,severity,ai_related,matched,ai_signal,updated_at)
                VALUES(?,?,1,?, 'strong', ?)""",
                (key, sev, json.dumps([f"pip/{pkg}"]), now_iso()))
            n_new += 1
            n_meta += 1
        time.sleep(0.8)   # 无 token 60/h，31 包需控制
    store.db.commit()
    print(f"[gha] 查询 {len(pkgs)} 个 AI 包，新增 {n_new} 条 advisory（含精确版本区间）")


# ---------- main ----------

def ensure_meta_table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS vuln_meta(
        cve_id TEXT PRIMARY KEY, cvss REAL, severity TEXT, kev INTEGER, epss TEXT,
        cpes TEXT, ai_related INTEGER, matched TEXT, ai_signal TEXT DEFAULT '', updated_at TEXT)""")
    cols = {r[1] for r in db.execute("PRAGMA table_info(vuln_meta)").fetchall()}
    if "ai_signal" not in cols:
        db.execute("ALTER TABLE vuln_meta ADD COLUMN ai_signal TEXT DEFAULT ''")
    db.commit()


def main():
    ap = argparse.ArgumentParser(description="漏洞线+论文线采集器")
    ap.add_argument("--source", default="all",
                    choices=["all", "nvd", "kev", "epss", "osv", "arxiv", "gha"])
    ap.add_argument("--lookback", type=int, default=0, help="NVD 回看天数（0=配置值30）")
    ap.add_argument("--max-packages", type=int, default=0, help="OSV 只查前 N 个包（试跑）")
    ap.add_argument("--max-papers", type=int, default=50, help="arXiv 每主题最多几篇")
    ap.add_argument("--out-dir", default="./data", help="数据目录")
    ap.add_argument("--config", default="config.json")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    cfg_p = root / args.config if not Path(args.config).is_absolute() else Path(args.config)
    cfg = json.loads(cfg_p.read_text(encoding="utf-8")) if cfg_p.exists() else {}
    vuln_cfg = cfg.get("vuln", {})
    vuln_cfg["out_dir"] = args.out_dir
    if args.lookback:
        vuln_cfg["lookback_days"] = args.lookback

    store = Store(Path(args.out_dir))
    ensure_meta_table(store.db)
    src = args.source
    phases = {"nvd": lambda: run_nvd(vuln_cfg, store, int(vuln_cfg.get("lookback_days", 30))),
              "kev": lambda: run_kev(vuln_cfg, store),
              "epss": lambda: run_epss(vuln_cfg, store),
              "osv": lambda: run_osv(vuln_cfg, store, args.max_packages),
              "arxiv": lambda: run_arxiv(vuln_cfg, store, args.max_papers),
              "gha": lambda: run_github_advisory(vuln_cfg, store)}
    order = ["nvd", "kev", "epss", "osv", "gha", "arxiv"] if src == "all" else [src]
    for name in order:   # 源间故障隔离：一个源崩不影响其余
        try:
            phases[name]()
        except Exception as e:
            print(f"[{name}] 阶段失败: {type(e).__name__}: {e}")

    stats = store.db.execute("""SELECT ai_related, count(*) FROM vuln_meta GROUP BY ai_related""").fetchall()
    print(f"vuln_meta 概览: AI相关/全部 = {stats}")


if __name__ == "__main__":
    main()

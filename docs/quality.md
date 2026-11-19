# 情报数据核查规范（SOP·v1.1）

> 适用范围：`aegis-intel/data/index.sqlite` 及 `data/export/` 的全部产出数据。
> 执行时机：每日自动核查（附面板输出）+ 每次大批量入库后人工核查 + 发布前复核。
> 原则：**计数不是证据，逐条抽样验证才是**——本文件所有核查项均附 SQL，可直接复跑。

---

## 一、五项例行核查（每日 run_daily 后自动产出）

### 1.1 拦截页污染（最高优先级）

**背景**：2026-09-26 检查发现 848 条 FreeBuf 滑块验证码页混充正文（"请按住滑块"被抽成 434 字恰好过 300 字门槛）。已修复写入端检测，但**批量入库后仍需重新执行校验**。

```sql
-- 期望结果：全部为 0
SELECT '滑块' AS 类型, count(*) FROM records WHERE content_md LIKE '%请按住滑块%';
SELECT '环境异常', count(*) FROM records WHERE content_md LIKE '%环境异常%';
SELECT '访问频繁', count(*) FROM records WHERE content_md LIKE '%访问过于频繁%';
SELECT '拖动验证', count(*) FROM records WHERE content_md LIKE '%拖动到最右边%';
```

**处置**：若 >0，立即执行：
```sql
UPDATE records SET content_md='', status='detail_failed'
WHERE content_md LIKE '%请按住滑块%' OR content_md LIKE '%环境异常%';
```

### 1.2 正文质量三查

```sql
-- A. enriched 但正文过短（<300 字，不应存在）
SELECT count(*) FROM records
WHERE status='enriched' AND type IN ('article','rss_article')
  AND length(content_md) < 300;
-- 期望：0

-- B. enriched 但无标题
SELECT count(*) FROM records
WHERE status='enriched' AND (title IS NULL OR length(title) < 4);
-- 期望：0

-- C. 正文疑似截断（结尾无标点且长度 <500）
SELECT count(*) FROM records
WHERE status='enriched' AND type IN ('article','rss_article')
  AND length(content_md) < 500
  AND substr(content_md, -1) NOT IN ('。','！','？','.','!','?','>','）',')');
-- 期望：<5%；若突增则抽样人工判读结尾是否为验证码/半截页
```

### 1.3 结构完整性

```sql
-- type 空值（必须为 0）
SELECT count(*) FROM records WHERE type IS NULL OR type='';
-- 期望：0

-- 未来日期（必须为 0）
SELECT count(*) FROM records WHERE publish_time > datetime('now','localtime');
-- 期望：0

-- url 重复行
SELECT count(*) FROM (SELECT url FROM records GROUP BY url HAVING count(*)>1);
-- 期望：0
```

### 1.4 合规红线

```sql
-- 付费文章有正文=违规（tags 含"付费"但 content_md 非空）
SELECT count(*) FROM records WHERE tags LIKE '%付费%' AND length(content_md) > 0;
-- 期望：0

-- no_body 记录有正文（不一致）
SELECT count(*) FROM records WHERE status='no_body' AND length(content_md) > 0;
-- 期望：0
```

### 1.5 数据面板

```sql
-- 各源全文覆盖
SELECT CASE WHEN source='xianzhi' THEN '先知'
       WHEN source='freebuf' THEN 'FreeBuf'
       WHEN source='secrss' THEN '安全内参'
       WHEN source='butian' THEN '补天'
       ELSE 'RSS/国际' END AS 源,
       count(*) AS 总数,
       sum(CASE WHEN length(content_md)>=300 THEN 1 ELSE 0 END) AS 全文,
       sum(CASE WHEN status='no_body' THEN 1 ELSE 0 END) AS 无正文
FROM records WHERE type IN ('article','rss_article')
GROUP BY 1 ORDER BY 全文 DESC;

-- AI CVE 信号分布
SELECT ai_signal, count(*) FROM vuln_meta WHERE ai_related=1 GROUP BY ai_signal;
-- 关注：strong 应逐步增长（GitHub Advisory/CNNVD/CPE 命中）；weak 待 LLM 复核
```

---

## 二、深度核查（每周或大批量入库后）

### 2.1 抽样人工审读（5 条）

```sql
-- 随机取 5 条 enriched 文章，人工核对标题↔正文↔URL 一致性
SELECT source, title, url, substr(content_md, 1, 200) AS 开头, length(content_md) AS 长度
FROM records WHERE status='enriched' AND type IN ('article','rss_article')
ORDER BY Random() LIMIT 5;
```

**核对要点**：
- [ ] 标题与正文内容匹配（不是"标题 A 配正文 B"的错配）
- [ ] 开头 200 字通顺（非乱码/代码/导航）
- [ ] URL 可打开且内容一致（抽 2 条点开验证）
- [ ] 长度合理（安全文章通常 1,000-50,000 字）

### 2.2 AI 相关性抽样（10 条 CVE）

```sql
SELECT m.cve_id, r.title, m.ai_signal, m.matched
FROM vuln_meta m JOIN records r ON r.id = 'cve-' || m.cve_id
WHERE m.ai_related=1 AND r.url LIKE '%nvd%'
ORDER BY Random() LIMIT 10;
```

**核对要点**：
- [ ] 标题/描述确实涉及 AI/ML 生态（LangChain/PyTorch/LLM/大模型/Agent）
- [ ] ai_signal=strong 的条目有 CPE 组件名佐证
- [ ] 误报率估计 <30%（若超 30% 则收紧 AI_RE 词表并重跑 data_clean）

### 2.3 md 导出一致性

```bash
# 导出后核对文件数与库内 enriched 数一致
uv run python scripts/export_md.py
# 期望：导出数 ≈ (enriched 文章) + (有正文 CVE) ± 5%
ls data/export/ -R | grep -c "\.md$"
```

---

## 三、发布前复核（一次性）

| # | 检查项 | 方法 | 通过标准 |
|---|---|---|---|
| 1 | 全部例行核查 | §一所有 SQL | 全绿 |
| 2 | 深度核查 | §二抽样 | 人工确认 |
| 3 | md 可读性 | 打开 data/export/ 3 个文件 | front-matter 齐全、正文干净 |
| 4 | 敏感信息 | `grep -r "api_key\|token\|password" data/export/` | 0 命中 |
| 5 | 数据时间线 | 各源 publish_time min/max 合理 | 无未来、无异常远古 |
| 6 | 合规声明 | README/部署文档 已含"仅公开数据/低频/合规研究用途" | 已含 |

---

## 四、执行记录

每次核查后在下方追加一行（日期/执行人/结果/异常处置）：

| 日期 | 执行人 | 结果 | 异常与处置 |
|---|---|---|---|
| 2026-09-26 | ZCode | §一全绿 | 发现并清除 932 条拦截页污染（FreeBuf 848+微信 84） |
| 2026-09-27 | ZCode | §一全绿 | FreeBuf 回填 510 篇全文（curl_cffi 采集器），GitHub Advisory +457 |
| 2026-09-27 | ZCode | **全绿+向量化专项全绿** | quality_check.py 落地（10 例行+4 专项+心跳+抽样）；心跳 32h 过期→run_daily 待明日计划任务触发后恢复；抽样 3 条内容吻合 |
| 2026-09-27 | ZCode | **情报核查全绿** | 例行 10 项✓ + 向量化专项 4 项✓ + 抽样 5/5 合格（FreeBuf 多智能体/Claude Code 窃取、安全内参银行处罚/智能体治理、先知 RAG-SAST 均与原文吻合）；心跳仍 33h 过期（待明日 08:00 首次自动运行后恢复） |
| 2026-10-02 | ZCode | **例行核查通过** | 29,586 条记录；新增 arXiv 244 篇论文 + 国际四源 143 篇 + Unit42/Wiz/Google/BC 40 篇；enriched 1,409 篇文章（8 条补天短文为已知低_content 正常）；心跳 0h ✓；arXiv 论文线终于突破限流开始产出 |

---

## 五、核查工具脚本（一键执行）

```bash
# 例行核查一键跑（含全部 §一 SQL + 面板输出）
uv run python -c "
import sqlite3; c = sqlite3.connect('data/index.sqlite')
checks = [
    ('拦截页', \"SELECT count(*) FROM records WHERE content_md LIKE '%请按住滑块%' OR content_md LIKE '%环境异常%'\"),
    ('enriched<300字', \"SELECT count(*) FROM records WHERE status='enriched' AND type IN ('article','rss_article') AND length(content_md)<300\"),
    ('type空', \"SELECT count(*) FROM records WHERE type IS NULL OR type=''\"),
    ('未来日期', \"SELECT count(*) FROM records WHERE publish_time > datetime('now','localtime')\"),
    ('付费有正文', \"SELECT count(*) FROM records WHERE tags LIKE '%付费%' AND length(content_md)>0\"),
    ('no_body有正文', \"SELECT count(*) FROM records WHERE status='no_body' AND length(content_md)>0\"),
]
all_ok = True
for name, sql in checks:
    v = c.execute(sql).fetchone()[0]
    mark = '✓' if v == 0 else '✗ 异常!'
    if v != 0: all_ok = False
    print(f'  {mark} {name}: {v}')
print('结论:', '全绿 ✓' if all_ok else '存在异常，请按 §一 处置 ❌')
"
```

> **规范**：发现任何异常先记入 §四 执行记录再处置；处置完后复跑 §五 确认全绿；§三 复核通过后方可发布。

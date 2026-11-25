import type { NormalizedQA } from '../types/contract';

/**
 * 纯前端将单轮 AI 研判结果生成标准 Markdown 简报并触发下载
 */
export function buildQABriefMarkdown(query: string, response: NormalizedQA): string {
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const lines: string[] = [
    `# Aegis Intel 安全情报研判简报`,
    ``,
    `- **研判问题**：${query}`,
    `- **生成时间**：${now}`,
    `- **执行路由**：\`${response.route?.reason || response.route?.branch || '-'}\``,
    `- **防幻觉校验**：${response.fabrications === 0 ? '通过（0 幻觉）' : `拦截 ${response.fabrications} 处`}`,
    response.elapsed_s !== undefined ? `- **响应耗时**：${response.elapsed_s.toFixed(1)}s` : '',
    ``,
    `## 研判结论`,
    ``,
    response.answer || '（暂无结论）',
    ``,
  ].filter((v) => v !== undefined);

  if (response.cards && response.cards.length > 0) {
    lines.push(`## 关联漏洞详情 (${response.cards.length})`, ``);
    lines.push(`| CVE 编号 | 风险等级 | CVSS | KEV 在野 | 受影响组件 | 攻击类型 |`);
    lines.push(`| :--- | :--- | :---: | :---: | :--- | :--- |`);
    for (const c of response.cards) {
      lines.push(
        `| [${c.cve_id}](${c.url || '#'}) | ${c.severity} | ${c.cvss ?? '-'} | ${c.kev === 1 ? '是' : '否'} | ${c.affected_component || '-'} | ${c.attack_type || '-'} |`
      );
    }
    lines.push(``);
    for (const c of response.cards) {
      if (c.remediation_zh) {
        lines.push(`### ${c.cve_id} 修复建议`, ``, c.remediation_zh, ``);
      }
    }
  }

  if (response.hits && response.hits.length > 0) {
    lines.push(`## 检索证据溯源 (${response.hits.length})`, ``);
    response.hits.forEach((h, i) => {
      const scoreStr = typeof h.score === 'number' ? ` (相关度 ${h.score.toFixed(3)})` : '';
      const titleLink = h.url ? `[${h.title || '情报片段'}](${h.url})` : h.title || '情报片段';
      lines.push(
        `${i + 1}. **[${(h.domain || 'INTEL').toUpperCase()}]** ${titleLink} — ${h.source || '未知来源'} · ${h.publish_time || '-'}${scoreStr}`
      );
    });
    lines.push(``);
  }

  return lines.join('\n');
}

export function downloadQABriefMarkdown(query: string, response: NormalizedQA): string {
  const md = buildQABriefMarkdown(query, response);
  const cveMatch = query.match(/CVE-\d{4}-\d{4,7}/i);
  const slug = cveMatch ? cveMatch[0].toUpperCase() : `brief-${Date.now().toString().slice(-6)}`;
  const filename = `aegis-intel-${slug}.md`;

  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return filename;
}

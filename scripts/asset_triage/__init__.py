# -*- coding: utf-8 -*-
"""资产暴露面研判（asset triage）子包。

把 Aegis Intel 的漏洞情报能力，接到企业组件与版本清单上：
清单接入 → 结构化区间比对 → 证据化结论 → 变更工单草稿 → 负责人审批。
"""

from .models import (Asset, Advisory, Finding, RangeParseError, compute_priority,
                     evidence_digest, norm_ecosystem, norm_package,
                     normalize_range, version_in_range)
from .store import Store

__all__ = [
    "Asset", "Advisory", "Finding", "RangeParseError", "compute_priority",
    "evidence_digest", "norm_ecosystem", "norm_package", "normalize_range",
    "version_in_range", "Store",
]

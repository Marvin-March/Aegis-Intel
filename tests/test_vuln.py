"""漏洞线纯函数测试：AI 词边界匹配 / NVD 记录构造 / EPSS 解析 / AI 信号分级。"""
from vuln_collector import match_ai, nvd_records, parse_epss_csv


def test_match_ai_positive():
    assert set(match_ai("PyTorch torch.export.load deserialization RCE in ComfyUI")) >= {"pytorch", "comfyui"}
    assert "llm" in match_ai("LLM prompt injection defense")


def test_match_ai_negative():
    assert match_ai("Heap overflow in Dubai weather API service") == []
    assert match_ai("training for a marathon") == []   # train 词内含无边界匹配的回归测试


def _cve_json(cpe=None, desc="Some vulnerability description.", cid="CVE-2026-9999"):
    return {
        "id": cid,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": c} for c in (cpe or [])]}]}],
        "references": [{"url": "https://example.com/a"}],
        "published": "2026-09-23T10:00:00.000",
    }


def test_nvd_records_ai_strong_via_cpe():
    rec, meta = nvd_records(_cve_json(cpe=["cpe:2.3:a:langchain:langchain:0.1:*:*:*:*:*:*:*"]))
    assert meta["ai_signal"] == "strong"
    assert meta["ai_related"] == 1
    assert "langchain" in meta["matched"]
    assert rec["id"] == "cve-CVE-2026-9999"
    assert rec["type"] == "cve"
    assert "- CVSS: 9.8 (CRITICAL)" in rec["content_md"]


def test_nvd_records_ai_weak_via_desc():
    rec, meta = nvd_records(_cve_json(desc="A flaw in the LLM prompt handler allows bypass."))
    assert meta["ai_signal"] == "weak"
    assert meta["ai_related"] == 1


def test_nvd_records_none():
    rec, meta = nvd_records(_cve_json(desc="Buffer overflow in a printer driver."))
    assert meta["ai_signal"] == "none"
    assert meta["ai_related"] == 0
    assert rec["tags"] and rec["tags"][0] == "cve"


def test_parse_epss_csv():
    from vuln_collector import parse_epss_csv
    text = "#model_version:v2026.01\ncve,epss,percentile\nCVE-2026-1,0.15,0.44\nCVE-2026-2,0.99,0.99"
    rows = parse_epss_csv(text)
    assert ("CVE-2026-1", "0.15") in rows and ("CVE-2026-2", "0.99") in rows

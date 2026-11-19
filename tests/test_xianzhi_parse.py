"""先知列表解析测试：fixture = 2026-09-24 真实抓取的 API 响应（data/raw 存档件）。"""
import json
import re
from pathlib import Path

import pytest

from xianzhi_crawler import Store, infer_record_type, max_page, parse_list_payload

FIXTURE = Path(__file__).parent / "fixtures" / "xianzhi_page1.json"


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path)


@pytest.fixture()
def payload():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_fields(store, payload):
    recs, all_seen = parse_list_payload(payload, store)
    assert len(recs) == 10
    assert all_seen is False          # 空库首抓，不应全部已存在
    r = recs[0]
    assert r["id"] == "xianzhi-92855"
    assert r["source"] == "xianzhi"
    assert r["type"] == "article"
    assert r["url"] == "https://xz.aliyun.com/news/92855"
    assert r["category"] == "AI专栏"
    assert r["views"] > 0
    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", r["publish_time"])
    assert r["author"] and r["summary"]


def test_all_seen_after_upsert(store, payload):
    recs, _ = parse_list_payload(payload, store)
    for r in recs:
        store.upsert(r, "listed")
    _, all_seen = parse_list_payload(payload, store)
    assert all_seen is True           # 已全部入库 → 增量早停条件成立


def test_max_page(payload):
    assert max_page(payload.get("pagination", "")) == 49


def test_infer_record_type():
    assert infer_record_type("https://xz.aliyun.com/news/1", "xianzhi") == "article"
    assert infer_record_type("https://www.freebuf.com/x", "rss:某源") == "rss_article"
    assert infer_record_type("https://nvd.nist.gov/vuln/detail/CVE-2026-1", "nvd") == "cve"
    assert infer_record_type("https://osv.dev/vulnerability/GHSA-x", "osv") == "advisory"

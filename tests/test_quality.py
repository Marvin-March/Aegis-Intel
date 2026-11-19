"""RSS/deep_fill 纯函数测试：关键词匹配 / 优选源判定 / 清洗。"""
from deep_fill import clean_md
from rss_collector import clean, is_deep_feed, match_keywords


def test_clean_strips_html():
    assert clean("<p>Hello&nbsp;World</p>", limit=100) == "Hello World"


def test_match_keywords_include_exclude():
    inc, exc = ["AI", "LLM", "大模型"], ["招聘"]
    assert match_keywords("大模型越狱研究", inc, exc) == "大模型"
    assert match_keywords("安全厂商招聘启事", inc, exc) is None
    assert match_keywords("普通新闻", inc, exc) is None


def test_is_deep_feed():
    feeds = ["https://api.anquanke.com/data/v1/rss"]
    assert is_deep_feed("https://api.anquanke.com/data/v1/rss", feeds)
    assert not is_deep_feed("https://example.com/rss", feeds)


def test_clean_md_unescape_and_strip():
    md = "<div>标题 &amp; 正文</div>"
    out = clean_md(md)
    assert "<div>" not in out and "&amp;" not in out
    assert "标题" in out and "正文" in out

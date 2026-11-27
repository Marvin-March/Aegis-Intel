"""Enterprise WeChat, Feishu and DingTalk robot messages."""

import base64
import hashlib
import hmac
import re
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests
from .integration_common import Delivery, http_failure, http_url, post, response_object

WEBHOOK_ENV = {
    "wecom": "WECOM_WEBHOOK_URL",
    "feishu": "FEISHU_WEBHOOK_URL",
    "dingtalk": "DINGTALK_WEBHOOK_URL",
}


def feishu_signature(secret, timestamp):
    key = f"{timestamp}\n{secret}".encode()
    return base64.b64encode(hmac.digest(key, b"", hashlib.sha256)).decode("ascii")


def dingtalk_signature(secret, timestamp):
    content = f"{timestamp}\n{secret}".encode()
    return base64.b64encode(hmac.digest(secret.encode("utf-8"), content, hashlib.sha256)).decode("ascii")


def truncate_utf8(value, limit):
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit - 3].decode("utf-8", errors="ignore") + "…"


def markdown_text(value, limit):
    # Keep source content from creating links, mentions or additional Markdown blocks.
    value = " ".join(value.split())
    escaped = re.sub(r"([\\\x60*_[\]~|])", r"\\\1", value)
    escaped = escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return truncate_utf8(escaped, limit)


def markdown_message(vuln):
    lines = [f"### 高危漏洞告警 {vuln.cve_id}"]
    for label, value in vuln.details().items():
        limit = 600 if label in {"中文摘要", "修复建议"} else 180
        lines.append(f"- **{label}**：{markdown_text(value, limit)}")
    if vuln.url:
        url = vuln.url.replace("(", "%28").replace(")", "%29").replace("<", "%3C").replace(">", "%3E")
        if len(url.encode("utf-8")) > 1000:
            url = f"https://www.cve.org/CVERecord?id={vuln.cve_id}"
        lines.append(f"- **溯源**：[查看公告]({url})")
    return "\n\n".join(lines)


def build_im_payload(platform, vuln):
    if platform == "feishu":
        content = [
            [{"tag": "text", "text": f"{label}：{value}"}]
            for label, value in vuln.details().items()
        ]
        if vuln.url:
            content.append([{"tag": "a", "text": "查看原文", "href": vuln.url}])
        return {
            "msg_type": "post",
            "content": {"post": {"zh_cn": {"title": f"高危漏洞告警 {vuln.cve_id}", "content": content}}},
        }
    message = markdown_message(vuln)
    if platform == "wecom":
        return {"msgtype": "markdown", "markdown": {"content": message}}
    if platform == "dingtalk":
        return {"msgtype": "markdown", "markdown": {"title": f"漏洞告警 {vuln.cve_id}", "text": message}}
    raise ValueError("Unknown IM platform")


def send_im(platform, vuln, env, timeout):
    url = http_url(env.get(WEBHOOK_ENV[platform]))
    payload = build_im_payload(platform, vuln)
    if platform == "feishu" and env.get("FEISHU_SIGN_SECRET"):
        timestamp = str(int(time.time()))
        payload.update(timestamp=timestamp, sign=feishu_signature(env["FEISHU_SIGN_SECRET"], timestamp))
    if platform == "dingtalk" and env.get("DINGTALK_SIGN_SECRET"):
        timestamp = str(time.time_ns() // 1_000_000)
        params = urlencode({"timestamp": timestamp, "sign": dingtalk_signature(env["DINGTALK_SIGN_SECRET"], timestamp)})
        parsed = urlsplit(url)
        query = "&".join(filter(None, (parsed.query, params)))
        url = urlunsplit(parsed._replace(query=query))

    try:
        response = post(url, json=payload, timeout=timeout)
    except requests.ConnectTimeout:
        return Delivery("failed", reason="ConnectTimeout")
    except requests.RequestException as exc:
        return Delivery("uncertain", reason=type(exc).__name__)

    if not 200 <= response.status_code < 300:
        return http_failure(response.status_code)
    body = response_object(response) or {}
    code = body.get("code", body.get("StatusCode")) if platform == "feishu" else body.get("errcode")
    if code == 0:
        return Delivery("sent")
    if isinstance(code, int):
        return Delivery("failed", reason=f"robot code {code}")
    return Delivery("uncertain", reason="Unrecognized robot response")

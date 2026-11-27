"""回归验证本机采集、人工确认和现有研判链之间的边界。"""

from __future__ import annotations

import csv
import json
import os
import socket
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from asset_triage import discovery
from asset_triage import tickets
from asset_triage.matcher import match
from asset_triage.store import Store, TicketTransitionError


@pytest.fixture
def store(tmp_path):
    with closing(Store(tmp_path / "assets.sqlite")) as result:
        yield result


def _dist(path: Path, name: str, version: str) -> Path:
    info = path / f"{name}-{version}.dist-info"
    info.mkdir(parents=True)
    metadata = info / "METADATA"
    metadata.write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
    return metadata


def _read(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _write(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, discovery.REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _accept(row: dict[str, str]) -> dict[str, str]:
    return {**row, "action": "confirm", "app_name": "推理服务", "owner": "张三",
            "environment": "prod", "exposure": "internal", "criticality": "high"}


def _observation(name: str, version: str) -> discovery.Observation:
    return discovery.Observation("pypi", name, version, "python-metadata", "test-site")


def _advisory():
    return {
        "advisory_id": "DEMO-001", "cve_id": "", "ecosystem": "pypi", "package": "demo-pkg",
        "range_raw": "<2", "range_normalized": "<2", "first_patched": "2",
        "severity": "high", "cvss": 8, "kev": 0, "published_at": "", "summary": "",
        "url": "", "source": "fixture", "fetched_at": "",
    }


def test_cli_local_handoff_enters_existing_matcher(tmp_path):
    site = tmp_path / "site-packages"
    _dist(site, "Demo_Pkg", "1.0")
    report, review, db = [tmp_path / name for name in ("discovery.json", "review.csv", "test.sqlite")]

    def cli(*args, expected=0):
        run = subprocess.run(
            [sys.executable, str(SCRIPTS / "asset_triage_cli.py"), "--db", str(db), *map(str, args)],
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        assert run.returncode == expected, run.stdout + run.stderr

    cli("discover", "--scope", "inference-prod", "--python-site", site, "--report", report, "--report-only")
    assert not db.exists()
    assert json.loads(report.read_text(encoding="utf-8"))["observations"][0]["component"] == "demo-pkg"
    cli("discover-import", report, "--scope", "different-scope", expected=2)
    assert not db.exists()
    cli("discover-import", report, "--scope", "inference-prod")
    cli("match", expected=1)
    cli("review-export", "--out", review, "--scope", "inference-prod")
    _write(review, [_accept(_read(review)[0])])
    cli("review-apply", review, "--actor", "李四")
    advisory_file = tmp_path / "advisories.json"
    advisory_file.write_text(json.dumps([_advisory()]), encoding="utf-8")
    cli("sync", "--from-file", advisory_file)
    cli("match", "--out-dir", tmp_path)
    cli("draft", "--approver", "李四", "--out-dir", tmp_path / "tickets")
    result = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
    assert result["findings"][0]["installed_version"] == "1.0"
    assert len(list((tmp_path / "tickets").glob("CHG-*.md"))) == 1
    with closing(Store(db)) as stored:
        evidence = json.loads(stored.list_assets()[0]["evidence_json"])
        assert evidence["reviewed_by"] == "李四"
        assert evidence["observations"][0]["source"] == "python-metadata"
        assert evidence["observations"][0]["collector_host"] == socket.gethostname()
    cli("review-apply", review, "--actor", "李四", expected=2)


def test_changed_version_invalidates_old_review_and_work_order(store, tmp_path):
    review = tmp_path / "review.csv"
    discovery.stage_observations(store, "api", [_observation("demo-pkg", "1")], "now")
    discovery.export_review(store, review)
    _write(review, [_accept(_read(review)[0])])
    discovery.apply_reviews(store, review, "reviewer", "now")
    discovery.stage_observations(store, "api", [_observation("demo-pkg", "1")], "later")
    assert discovery.export_review(store, review) == 0

    store.upsert_advisories([_advisory()])
    findings, _, _ = match(store.list_assets(confirmed_only=True), [_advisory()])
    store.replace_findings("run", findings)
    ids = [f["finding_id"] for f in findings]
    ticket = tickets.build_draft(store, ids, approver="reviewer")["tickets"][0]
    store.insert_ticket(ticket)
    tickets.submit(store, ticket["ticket_id"], "张三")

    discovery.stage_observations(store, "api", [_observation("demo-pkg", "2")], "later")
    assert discovery.export_review(store, review) == 1
    row = _read(review)[0]
    assert row["owner"] == "张三"
    assert store.list_assets()[0]["version"] == "1"
    assert store.list_assets(confirmed_only=True) == []
    assert store.list_findings() == []
    with pytest.raises(TicketTransitionError, match="待重新确认"):
        tickets.decide(store, ticket["ticket_id"], "reviewer", True, "同意")

    discovery.stage_observations(store, "api", [_observation("demo-pkg", "3")], "later")
    _write(review, [_accept(row)])
    with pytest.raises(ValueError, match="证据或审核记录已变化"):
        discovery.apply_reviews(store, review, "reviewer", "later")
    discovery.export_review(store, review)
    _write(review, [_accept(_read(review)[0])])
    discovery.apply_reviews(store, review, "reviewer", "later")
    assert store.list_assets(confirmed_only=True)[0]["version"] == "3"
    assert store.list_findings() == []


def test_manual_add_reject_and_review_batch_rollback(store, tmp_path):
    review = tmp_path / "review.csv"
    discovery.stage_observations(store, "api", [_observation("unrelated", "1")], "now")
    discovery.export_review(store, review)
    rejected = {**_read(review)[0], "action": "reject", "reason": "仅存在于辅助环境"}
    manual = {**_accept({}), "action": "add", "scope": "api", "ecosystem": "pypi",
              "component": "manual-pkg", "version": "2"}
    _write(review, [rejected, manual])
    with pytest.raises(ValueError, match="须填写 reason"):
        discovery.apply_reviews(store, review, "reviewer", "now")
    assert store.db.execute("SELECT count(*) FROM asset_review_event").fetchone()[0] == 0
    assert discovery.export_review(store, review) == 1
    _write(review, [rejected, {**manual, "reason": "部署记录已核对"}])
    assert discovery.apply_reviews(store, review, "reviewer", "now") == {"confirm": 0, "reject": 1, "add": 1}
    assert store.list_assets(confirmed_only=True)[0]["source"] == "manual-review"
    assert discovery.export_review(store, review) == 0
    assert discovery.export_review(store, review, include_reviewed=True) == 2
    rows = {item["component"]: item for item in _read(review)}
    _write(review, [_accept(rows["unrelated"])])
    discovery.apply_reviews(store, review, "reviewer", "now")
    assert len(store.list_assets(confirmed_only=True)) == 2


def test_lockfile_conflicting_versions_require_confirmation_evidence(store, tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"version": "0.1.0"},
        "node_modules/@scope/pkg": {"version": "1.2.0", "dev": True},
        "node_modules/consumer/node_modules/@scope/pkg": {"version": "2.1.0"},
    }}), encoding="utf-8")
    candidates = discovery.npm_observations(lock)
    assert {item.source for item in candidates} == {"npm-lock", "npm-lock-dev"}
    discovery.stage_observations(store, "api", candidates, "now")
    review = tmp_path / "review.csv"
    discovery.export_review(store, review)
    row = _accept(_read(review)[0])
    assert row["version"] == ""
    assert row["observed_versions"] == "1.2.0 | 2.1.0"
    assert row["component"] == "'@scope/pkg"
    _write(review, [{**row, "version": "2.1.0"}])
    with pytest.raises(ValueError, match="须填写 reason"):
        discovery.apply_reviews(store, review, "reviewer", "now")
    _write(review, [{**row, "version": "2.1.0", "reason": "部署记录确认实际版本"}])
    discovery.apply_reviews(store, review, "reviewer", "now")
    assert store.list_assets(confirmed_only=True)[0]["component"] == "@scope/pkg"


def test_tcp_observation_reads_a_real_local_listener():
    pytest.importorskip("psutil")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        listeners = discovery.local_tcp_listeners()
    assert any(item["port"] == port and item["address"] == "127.0.0.1" for item in listeners)


def test_report_replay_and_out_of_order_delivery(store, tmp_path):
    path = tmp_path / "report.json"
    report = {"schema_version": 1, "scope": "api", "collector_host": "host-a",
              "collected_at": "2026-11-25T10:00:00+08:00", "observations": [{
                  "ecosystem": "pypi", "component": "demo-pkg", "version": "2.0",
                  "source": "python-metadata", "location": "/demo/site-packages",
              }]}
    path.write_text(json.dumps(report), encoding="utf-8")
    scope, time, rows = discovery.read_report(path)
    assert time == "2026-11-25T02:00:00.000000+00:00"
    assert discovery.stage_observations(store, scope, rows, time, ordered_snapshot=True) == 1
    assert discovery.stage_observations(store, scope, rows, time, ordered_snapshot=True) == 0
    report["collected_at"] = "2026-11-25T01:59:59+00:00"
    report["observations"][0]["version"] = "1.0"
    path.write_text(json.dumps(report), encoding="utf-8")
    scope, time, rows = discovery.read_report(path)
    with pytest.raises(ValueError, match="旧报告不能覆盖"):
        discovery.stage_observations(store, scope, rows, time, ordered_snapshot=True)
    evidence = store.db.execute("SELECT observations_json FROM asset_candidate").fetchone()[0]
    assert json.loads(evidence)[0]["version"] == "2.0"

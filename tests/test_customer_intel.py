"""The customer entry point scopes collection, review, alert selection and delivery."""

import csv
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import customer_intel_cli
from asset_triage import discovery
from asset_triage.store import Store


def advisory(identifier, package, affected, *, cvss=8, kev=0, ecosystem="pypi"):
    return {"advisory_id": identifier, "ecosystem": ecosystem, "package": package,
            "range_raw": affected, "first_patched": "1.0", "cvss": cvss, "kev": kev,
            "severity": "HIGH" if cvss >= 7 else "LOW", "url": f"https://example.invalid/{identifier}"}


class CustomerIntelTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.db = self.root / "index.sqlite"
        self.review = self.root / "review.csv"

    def call(self, *args, prefix=(), expected=0):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = customer_intel_cli.main(["--db", str(self.db), *prefix, *map(str, args)])
        self.assertEqual(status, expected, out.getvalue() + err.getvalue())
        return out.getvalue()

    def package(self, site, name, version):
        path = site / f"{name}-{version}.dist-info" / "METADATA"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")

    def collect(self, customer, *packages, prefix=()):
        site = self.root / customer
        site.mkdir(exist_ok=True)
        for name, version in packages:
            self.package(site, name, version)
        self.call("collect", "--customer", customer, "--deployment", "api",
                  "--python-site", site, prefix=prefix)
        return site

    def confirm(self, customer):
        store = Store(self.db)
        try:
            discovery.export_review(store, self.review, f"{customer}/api")
            with self.review.open(encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            with self.review.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, discovery.REVIEW_COLUMNS)
                writer.writeheader()
                writer.writerows({
                    **row, "action": "confirm", "app_name": "AI Service", "owner": "Reviewer",
                    "environment": "prod", "exposure": "internal", "criticality": "high",
                } for row in rows)
            discovery.apply_reviews(store, self.review, "Reviewer", "2026-11-25")
            return {row["component"] for row in rows}
        finally:
            store.close()

    def sync(self, customer, *advisories):
        notice_file = self.root / "advisories.json"
        notice_file.write_text(json.dumps(advisories), encoding="utf-8")
        self.call("sync", "--customer", customer, "--from-file", notice_file)

    def preview(self, customer, *args, prefix=()):
        return json.loads(self.call("push", "--customer", customer, *args, prefix=prefix))

    def test_exact_ai_catalog_and_customer_version_gate(self):
        self.collect("alpha", ("vllm", "0.8"), ("requests", "2.33"), ("nemoguardrails", "0.20"))
        self.collect("alpha-inc", ("vllm", "2.2"), ("litellm", "1.0"))
        self.assertEqual(self.preview("alpha")["alerts"], [])
        self.assertEqual(self.confirm("alpha"), {"vllm", "nemoguardrails"})
        self.assertEqual(self.confirm("alpha-inc"), {"vllm", "litellm"})
        self.sync("alpha",
                  advisory("ADV-VLLM", "vllm", "<1"),
                  advisory("ADV-REQUESTS", "requests", "<9"),
                  advisory("ADV-GUARD", "nemoguardrails", "<1", cvss=2, kev=1),
                  advisory("ADV-OTHER", "litellm", "<2"),
                  advisory("ADV-NPM", "vllm", "<9", ecosystem="npm"),
                  advisory("ADV-INVALID", "vllm", "unknown"))
        result = self.preview("alpha")
        self.assertEqual([item["notice"] for item in result["alerts"]], ["ADV-GUARD", "ADV-VLLM"])
        self.assertEqual(result["unparsed_pairs"], 1)
        self.assertIn("vllm 0.8", result["alerts"][1]["evidence"]["客户组件命中"])
        self.assertEqual([item["notice"] for item in self.preview("alpha-inc")["alerts"]], ["ADV-OTHER"])
        self.assertEqual([item["notice"] for item in
                          self.preview("alpha", prefix=("--category", "security"))["alerts"]], ["ADV-GUARD"])

    def test_collect_security_tools_only(self):
        self.collect("alpha", ("vllm", "0.8"), ("nemoguardrails", "0.20"),
                     ("requests", "2.33"), prefix=("--category", "security"))
        self.assertEqual(self.confirm("alpha"), {"nemoguardrails"})

    def test_disappeared_component_waits_for_review(self):
        site = self.collect("alpha", ("vllm", "0.8"))
        self.confirm("alpha")
        self.sync("alpha", advisory("ADV-VLLM", "vllm", "<1"))
        self.assertEqual(len(self.preview("alpha")["alerts"]), 1)
        (site / "vllm-0.8.dist-info" / "METADATA").unlink()
        self.collect("alpha", ("requests", "2.33"))
        self.assertEqual(self.preview("alpha")["alerts"], [])
        store = Store(self.db)
        try:
            discovery.export_review(store, self.review, "alpha/api")
            with self.review.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["sources"], "missing-from-snapshot")
            self.assertEqual(row["version"], "")
        finally:
            store.close()

    def test_import_report_preserves_customer_scope_and_filter(self):
        report = self.root / "snapshot.json"
        report.write_text(json.dumps({
            "schema_version": 1, "scope": "api", "collector_host": "demo-host",
            "collected_at": "2026-11-25T09:00:00+08:00",
            "observations": [{"component": name, "version": "1", "ecosystem": "pypi",
                              "source": "python-metadata", "location": "/demo"}
                             for name in ("vllm", "requests")],
        }), encoding="utf-8")
        self.call("collect", "--customer", "alpha", "--deployment", "app", "--from-report", report,
                  expected=2)
        self.call("collect", "--customer", "alpha", "--deployment", "api", "--from-report", report)
        self.assertEqual(self.confirm("alpha"), {"vllm"})

    def test_customer_webhook_binding_dedupe_and_escalation(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"errcode":0}')

            def log_message(self, *_args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Receiver) as receiver:
            thread = threading.Thread(target=receiver.serve_forever, daemon=True)
            thread.start()
            try:
                port = receiver.server_address[1]
                env = self.root / "alpha.env"
                env.write_text(f"AEGIS_CUSTOMER_ID=alpha\nWECOM_WEBHOOK_URL=http://127.0.0.1:{port}/robot\n",
                               encoding="utf-8")
                self.collect("alpha", ("vllm", "0.8"))
                self.confirm("alpha")
                self.sync("alpha", advisory("ADV-VLLM", "vllm", "<1"))
                self.call("push", "--customer", "other", "--env-file", env, "--send", expected=2)
                self.assertEqual(len(self.preview("alpha", "--env-file", env)["alerts"]), 1)
                self.assertEqual(received, [])
                self.call("push", "--customer", "alpha", "--env-file", env, "--send")
                self.call("push", "--customer", "alpha", "--env-file", env, "--send")
                self.assertEqual(len(received), 1)
                self.assertIn("vllm 0.8", received[0]["markdown"]["content"])
                self.assertNotIn("Reviewer", received[0]["markdown"]["content"])
                self.sync("alpha", advisory("ADV-VLLM", "vllm", "<1", kev=1))
                self.call("push", "--customer", "alpha", "--env-file", env, "--send")
                self.assertEqual(len(received), 2)
            finally:
                receiver.shutdown()
                thread.join()


if __name__ == "__main__":
    unittest.main()

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("astra_diff", Path(__file__).resolve().parents[1] / "tools/astra-diff.py")
diff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diff)


def endpoint(state="open"):
    return {"address": "127.0.0.1", "port": 22, "transport": "tcp", "state": state, "service": "ssh", "tls": {}}


class DiffTests(unittest.TestCase):
    def test_state_change(self):
        key = ("127.0.0.1", 22, "tcp")
        result = diff.compare({key: endpoint()}, {key: endpoint("closed")})
        self.assertEqual(result["changes"][0]["fields"]["state"], {"before": "open", "after": "closed"})

    def test_scope_is_not_state(self):
        result = diff.compare({}, {("127.0.0.1", 22, "tcp"): endpoint()})
        self.assertEqual(result["changes"][0]["kind"], "scope_added")

    def test_timing_ignored(self):
        key = ("127.0.0.1", 22, "tcp")
        a, b = endpoint(), endpoint()
        a["latency_ms"], b["latency_ms"] = 1, 10
        self.assertEqual(diff.compare({key: a}, {key: b})["change_count"], 0)

    def test_tls_change(self):
        key = ("127.0.0.1", 22, "tcp")
        a, b = endpoint(), endpoint()
        b["tls"] = {"not_after": "new date"}
        self.assertIn("tls.not_after", diff.compare({key: a}, {key: b})["changes"][0]["fields"])

    def test_certificate_fingerprint_change(self):
        key = ("127.0.0.1", 22, "tcp")
        a, b = endpoint(), endpoint()
        a["tls"]["sha256"], b["tls"]["sha256"] = "a" * 64, "b" * 64
        self.assertIn("tls.sha256", diff.compare({key: a}, {key: b})["changes"][0]["fields"])

    def test_stable_http_header_change(self):
        key = ("127.0.0.1", 22, "tcp")
        a, b = endpoint(), endpoint()
        a["http"] = {"headers": [{"name": "server", "value": "before"}, {"name": "date", "value": "old"}]}
        b["http"] = {"headers": [{"name": "server", "value": "after"}, {"name": "date", "value": "new"}]}
        fields = diff.compare({key: a}, {key: b})["changes"][0]["fields"]
        self.assertIn("http.headers.server", fields)
        self.assertNotIn("http.headers.date", fields)

    def test_schema2_scope_and_deadline_validation(self):
        result = endpoint()
        report = {"schema_version": 2, "scanner": "AstraScan", "cancelled": False, "timed_out": False, "only_open": False,
                  "planned": 1, "completed": 1, "results": [result], "scope": {"transport": "tcp", "addresses": ["127.0.0.1"], "ports": [22]}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(report))
            self.assertEqual(len(diff.load_report(path)), 1)
            for bad in (report | {"timed_out": True}, report | {"scope": {"transport": "tcp", "addresses": ["127.0.0.1"], "ports": [23]}}, report | {"scope": {"transport": "udp", "addresses": ["127.0.0.1"], "ports": [22]}}):
                path.write_text(json.dumps(bad))
                with self.assertRaises(diff.ReportError):
                    diff.load_report(path)

    def test_udp_ambiguity_accepted(self):
        result = endpoint("open|filtered") | {"transport": "udp"}
        report = {"schema_version": 1, "scanner": "AstraScan", "cancelled": False, "only_open": False, "planned": 1, "completed": 1, "results": [result]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(report))
            self.assertIn(("127.0.0.1", 22, "udp"), diff.load_report(path))
            report["results"][0]["transport"] = "tcp"
            path.write_text(json.dumps(report))
            with self.assertRaises(diff.ReportError):
                diff.load_report(path)

    def test_scope_guard_cli(self):
        a = {"schema_version": 1, "scanner": "AstraScan", "cancelled": False, "only_open": False, "planned": 1, "completed": 1, "results": [endpoint()]}
        with tempfile.TemporaryDirectory() as tmp:
            before, after = Path(tmp)/"before.json", Path(tmp)/"after.json"
            before.write_text(json.dumps(a))
            a["results"][0]["port"] = 80
            after.write_text(json.dumps(a))
            self.assertEqual(diff.main([str(before), str(after), "--require-same-scope"]), 2)

    def test_report_validation(self):
        valid = {"schema_version": 1, "scanner": "AstraScan", "cancelled": False, "only_open": False, "planned": 1, "completed": 1, "results": [endpoint()]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_text(json.dumps(valid))
            self.assertEqual(len(diff.load_report(path)), 1)
            for field, value in [("cancelled", True), ("only_open", True), ("planned", 2), ("results", [endpoint(), endpoint()]), ("schema_version", 2)]:
                invalid = valid | {field: value}
                path.write_text(json.dumps(invalid))
                with self.assertRaises(diff.ReportError):
                    diff.load_report(path)


if __name__ == "__main__":
    unittest.main()

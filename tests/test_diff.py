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

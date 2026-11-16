import datetime as dt
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("astra_policy", Path(__file__).resolve().parents[1] / "tools/astra-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.rules = policy.validate_policy({"schema_version": 1, "rules": [{"network": "127.0.0.0/8", "allow_ports": [443], "require_tls_ports": [443], "min_cert_days": 7}]})
        self.endpoint = {"address": "127.0.0.1", "port": 443, "state": "open", "tls": {"handshake": True, "not_after": "Dec 31 00:00:00 2030 GMT"}}
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def evaluate(self):
        return policy.evaluate({"endpoint": self.endpoint}, self.rules, self.now)

    def test_allowed(self):
        self.assertEqual(self.evaluate()["violation_count"], 0)

    def test_unexpected_port(self):
        self.endpoint["port"] = 22
        self.assertEqual(self.evaluate()["violations"][0]["reason"], "unexpected_open_port")

    def test_expired_certificate(self):
        self.endpoint["tls"]["not_after"] = "Dec 31 00:00:00 2025 GMT"
        self.assertEqual(self.evaluate()["violations"][0]["reason"], "certificate_expiring")

    def test_missing_handshake(self):
        self.endpoint["tls"]["handshake"] = False
        self.assertEqual(self.evaluate()["violations"][0]["reason"], "tls_handshake_required")

    def test_inconclusive_fails(self):
        self.endpoint["state"] = "filtered"
        self.assertEqual(self.evaluate()["violations"][0]["reason"], "inconclusive_endpoint")

    def test_specific_rule_wins(self):
        self.rules.append({"network": "127.0.0.1/32", "allow_ports": []})
        self.assertEqual(self.evaluate()["violations"][0]["reason"], "unexpected_open_port")

    def test_unknown_policy_field_rejected(self):
        with self.assertRaises(ValueError):
            policy.validate_policy({"schema_version": 1, "rules": [], "typo": True})


if __name__ == "__main__":
    unittest.main()

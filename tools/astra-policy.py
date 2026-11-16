#!/usr/bin/env python3
"""Evaluate an AstraScan inventory against an explicit JSON exposure policy."""
import argparse
import datetime as dt
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys

# Share strict report validation with the installed sibling utility.
_path = Path(__file__).with_name("astra-diff.py")
if not _path.exists():
    _path = Path(__file__).with_name("astra-diff")
_spec = importlib.util.spec_from_file_location("astra_inventory", _path) if _path.suffix == ".py" else None
if _spec is None:
    from importlib.machinery import SourceFileLoader
    _spec = importlib.util.spec_from_loader("astra_inventory", SourceFileLoader("astra_inventory", str(_path)))
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("policy must use schema_version 1")
    if set(policy) - {"schema_version", "rules"}:
        raise ValueError("unknown policy field")
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("policy requires a nonempty rules list")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"network", "allow_ports", "require_tls_ports", "min_cert_days"}:
            raise ValueError("unknown policy rule field")
        ipaddress.ip_network(rule["network"], strict=True)
        for field in ("allow_ports", "require_tls_ports"):
            ports = rule.get(field, [])
            if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise ValueError(f"{field} must contain TCP port integers")
        days = rule.get("min_cert_days", 0)
        if type(days) is not int or not 0 <= days <= 36500:
            raise ValueError("min_cert_days must be in 0..36500")
    return rules


def evaluate(results, rules, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    violations = []
    for result in results.values():
        endpoint = {"address": result["address"], "port": result["port"]}
        address = ipaddress.ip_address(result["address"].split("%", 1)[0])
        # Most-specific network wins, and equal-prefix ties use the first rule.
        matches = [r for r in rules if address in ipaddress.ip_network(r["network"])]
        rule = max(matches, key=lambda r: ipaddress.ip_network(r["network"]).prefixlen) if matches else None
        if result["state"] in ("filtered", "error"):
            violations.append(endpoint | {"reason": "inconclusive_endpoint"})
            continue
        if result["state"] != "open":
            continue
        if rule is None or result["port"] not in rule.get("allow_ports", []):
            violations.append(endpoint | {"reason": "unexpected_open_port"})
        if rule and result["port"] in rule.get("require_tls_ports", []):
            tls = result.get("tls", {})
            if not tls.get("handshake"):
                violations.append(endpoint | {"reason": "tls_handshake_required"})
                continue
            try:
                expiry = dt.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=dt.timezone.utc)
            except (ValueError, KeyError, TypeError):
                violations.append(endpoint | {"reason": "certificate_expiry_unknown"})
                continue
            if expiry - now < dt.timedelta(days=rule.get("min_cert_days", 0)):
                violations.append(endpoint | {"reason": "certificate_expiring"})
    return {"schema_version": 1, "violation_count": len(violations), "violations": violations}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("policy")
    args = parser.parse_args(argv)
    try:
        results = inventory.load_report(args.report)
        rules = validate_policy(json.loads(Path(args.policy).read_text(encoding="utf-8")))
        result = evaluate(results, rules)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"astra-policy: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())

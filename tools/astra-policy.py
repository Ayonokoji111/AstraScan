#!/usr/bin/env python3
"""Evaluate an AstraScan inventory against a JSON exposure and coverage policy."""
import argparse
import datetime as dt
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys

_path = Path(__file__).with_name("astra-diff.py")
if not _path.exists():
    _path = Path(__file__).with_name("astra-diff")
_spec = importlib.util.spec_from_file_location("astra_inventory", _path) if _path.suffix == ".py" else None
if _spec is None:
    from importlib.machinery import SourceFileLoader
    _spec = importlib.util.spec_from_loader("astra_inventory", SourceFileLoader("astra_inventory", str(_path)))
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)


def port_list(ports, label):
    if not isinstance(ports, list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError(f"{label} must contain port integers")


def validate_coverage(coverage):
    if not isinstance(coverage, list):
        raise ValueError("required_scope must be a list")
    total = 0
    for item in coverage:
        if not isinstance(item, dict) or set(item) - {"address", "ports", "transport"}:
            raise ValueError("unknown required_scope field")
        ipaddress.ip_address(item["address"].split("%", 1)[0])
        port_list(item["ports"], "required_scope.ports")
        if not item["ports"] or item.get("transport", "tcp") not in ("tcp", "udp"):
            raise ValueError("required_scope needs nonempty ports and tcp/udp transport")
        total += len(item["ports"])
        if total > 1000000:
            raise ValueError("required_scope exceeds 1,000,000 endpoints")
    return coverage


def validate_policy(policy):
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        raise ValueError("policy must use schema_version 1")
    if set(policy) - {"schema_version", "rules", "required_scope"}:
        raise ValueError("unknown policy field")
    validate_coverage(policy.get("required_scope", []))
    rules = policy.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("policy requires a nonempty rules list")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) - {"network", "allow_ports", "allow_udp_ports", "require_tls_ports", "require_verified_tls_ports", "min_cert_days", "http_ports", "require_http_headers"}:
            raise ValueError("unknown policy rule field")
        ipaddress.ip_network(rule["network"], strict=True)
        for field in ("allow_ports", "allow_udp_ports", "require_tls_ports", "require_verified_tls_ports", "http_ports"):
            port_list(rule.get(field, []), field)
        headers = rule.get("require_http_headers", [])
        if not isinstance(headers, list) or any(not isinstance(h, str) or not h or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~" for c in h) for h in headers):
            raise ValueError("require_http_headers must contain lowercase HTTP field names")
        days = rule.get("min_cert_days", 0)
        if type(days) is not int or not 0 <= days <= 36500:
            raise ValueError("min_cert_days must be in 0..36500")
    return rules


def evaluate(results, rules, now=None, required_scope=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    violations = []
    observed = {(str(ipaddress.ip_address(r["address"])), r["port"], r.get("transport", "tcp")) for r in results.values()}
    for item in required_scope or []:
        for port in sorted(set(item["ports"])):
            endpoint = {"address": str(ipaddress.ip_address(item["address"])), "port": port, "transport": item.get("transport", "tcp")}
            if (endpoint["address"], port, endpoint["transport"]) not in observed:
                violations.append(endpoint | {"reason": "required_endpoint_not_scanned"})
    for result in results.values():
        transport = result.get("transport", "tcp")
        endpoint = {"address": result["address"], "port": result["port"], "transport": transport}
        address = ipaddress.ip_address(result["address"].split("%", 1)[0])
        matches = [r for r in rules if address in ipaddress.ip_network(r["network"])]
        rule = max(matches, key=lambda r: ipaddress.ip_network(r["network"]).prefixlen) if matches else None
        if result["state"] in ("filtered", "open|filtered", "error"):
            violations.append(endpoint | {"reason": "inconclusive_endpoint"})
            continue
        if result["state"] != "open":
            continue
        allowed = "allow_udp_ports" if transport == "udp" else "allow_ports"
        if rule is None or result["port"] not in rule.get(allowed, []):
            violations.append(endpoint | {"reason": "unexpected_open_port"})
        if not rule or transport != "tcp":
            continue
        required_tls = set(rule.get("require_tls_ports", [])) | set(rule.get("require_verified_tls_ports", []))
        if result["port"] in required_tls:
            tls = result.get("tls", {})
            if tls.get("handshake") is not True:
                violations.append(endpoint | {"reason": "tls_handshake_required"})
            else:
                if result["port"] in rule.get("require_verified_tls_ports", []) and (tls.get("verification_attempted") is not True or tls.get("verified") is not True):
                    violations.append(endpoint | {"reason": "verified_tls_required"})
                try:
                    expiry = dt.datetime.strptime(tls["not_after"], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=dt.timezone.utc)
                except (ValueError, KeyError, TypeError):
                    violations.append(endpoint | {"reason": "certificate_expiry_unknown"})
                else:
                    if expiry - now < dt.timedelta(days=rule.get("min_cert_days", 0)):
                        violations.append(endpoint | {"reason": "certificate_expiring"})
        if result["port"] in rule.get("http_ports", []):
            http = result.get("http", {})
            if http.get("headers_complete") is not True or type(http.get("status")) is not int or not 100 <= http["status"] <= 599:
                violations.append(endpoint | {"reason": "complete_http_headers_required"})
            else:
                present = {h["name"] for h in http.get("headers", []) if h.get("value", "").strip()}
                for header in rule.get("require_http_headers", []):
                    if header not in present:
                        violations.append(endpoint | {"reason": "http_header_missing", "header": header})
    return {"schema_version": 1, "violation_count": len(violations), "violations": violations}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("policy")
    args = parser.parse_args(argv)
    try:
        results = inventory.load_report(args.report)
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        rules = validate_policy(policy)
        result = evaluate(results, rules, required_scope=policy.get("required_scope", []))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(f"astra-policy: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 1 if result["violations"] else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Compare complete AstraScan JSON inventories without third-party packages."""
import argparse
import json
import ipaddress
import sys
from pathlib import Path


class ReportError(ValueError):
    pass


def load_report(path):
    with Path(path).open(encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get("schema_version") not in (1, 2):
        raise ReportError(f"{path}: expected an AstraScan schema version 1 or 2 report")
    if report.get("scanner") != "AstraScan":
        raise ReportError(f"{path}: unexpected scanner")
    if report.get("cancelled") is not False or report.get("only_open") is not False:
        raise ReportError(f"{path}: diff requires a complete report without --open")
    if not isinstance(report.get("results"), list):
        raise ReportError(f"{path}: missing results")
    if report.get("schema_version") == 2 and report.get("timed_out") is not False:
        raise ReportError(f"{path}: deadline-truncated or missing deadline metadata")
    results = report["results"]
    if (type(report.get("planned")) is not int or report["planned"] < 1
            or type(report.get("completed")) is not int
            or report["completed"] != report["planned"] or report["completed"] != len(results)):
        raise ReportError(f"{path}: incomplete inventory")
    inventory = {}
    for result in results:
        if not isinstance(result, dict):
            raise ReportError(f"{path}: invalid result")
        address, port, transport = result.get("address"), result.get("port"), result.get("transport")
        if not isinstance(address, str) or not address or type(port) is not int or not 1 <= port <= 65535 or transport not in ("tcp", "udp"):
            raise ReportError(f"{path}: invalid endpoint")
        if result.get("state") not in {"open", "closed", "filtered", "open|filtered", "error"}:
            raise ReportError(f"{path}: invalid state")
        ipaddress.ip_address(address.split("%", 1)[0])
        if transport == "tcp" and result["state"] == "open|filtered":
            raise ReportError(f"{path}: invalid TCP state")
        if not isinstance(result.get("http", {}), dict):
            raise ReportError(f"{path}: invalid HTTP observation")
        if not isinstance(result.get("tls"), dict):
            raise ReportError(f"{path}: invalid TLS observation")
        tls = result["tls"]
        for field in ("handshake", "verified", "verification_attempted"):
            if field in tls and type(tls[field]) is not bool:
                raise ReportError(f"{path}: invalid TLS boolean")
        http = result.get("http", {})
        headers = http.get("headers", [])
        if not isinstance(headers, list) or any(not isinstance(h, dict) or not isinstance(h.get("name"), str) or not isinstance(h.get("value"), str) for h in headers):
            raise ReportError(f"{path}: invalid HTTP headers")
        if "headers_complete" in http and type(http["headers_complete"]) is not bool:
            raise ReportError(f"{path}: invalid HTTP completeness")
        if "status" in http and (type(http["status"]) is not int or (http["status"] != 0 and not 100 <= http["status"] <= 599)):
            raise ReportError(f"{path}: invalid HTTP status")
        key = (address, port, transport)
        if key in inventory:
            raise ReportError(f"{path}: duplicate endpoint")
        inventory[key] = result
    if report.get("schema_version") == 2:
        scope = report.get("scope")
        if not isinstance(scope, dict) or scope.get("transport") not in ("tcp", "udp"):
            raise ReportError(f"{path}: missing scope manifest")
        addresses, ports = scope.get("addresses"), scope.get("ports")
        if (not isinstance(addresses, list) or not addresses or any(not isinstance(a, str) for a in addresses)
                or not isinstance(ports, list) or not ports or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)):
            raise ReportError(f"{path}: invalid scope manifest")
        if len(set(addresses)) != len(addresses) or len(set(ports)) != len(ports):
            raise ReportError(f"{path}: duplicate scope entry")
        address_set, port_set = set(addresses), set(ports)
        if len(addresses) * len(ports) != len(inventory) or any(
                a not in address_set or p not in port_set or t != scope["transport"] for a, p, t in inventory):
            raise ReportError(f"{path}: results do not cover the declared scope")
    return inventory


def compare(before, after):
    changes = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        fields = {}
        # Compare stable observations; timings, target aliases, and ephemeral banners are ignored.
        if old is None or new is None:
            kind = "scope_added" if old is None else "scope_removed"
        else:
            kind = "changed"
            for field in ("state", "service"):
                if old.get(field) != new.get(field):
                    fields[field] = {"before": old.get(field), "after": new.get(field)}
            for field in ("handshake", "protocol", "cipher", "subject", "issuer", "not_after", "verification_attempted", "verified", "sha256", "sans"):
                previous = old.get("tls", {}).get(field)
                current = new.get("tls", {}).get(field)
                if previous != current:
                    fields[f"tls.{field}"] = {"before": previous, "after": current}
            for field in ("status", "headers_complete"):
                previous, current = old.get("http", {}).get(field), new.get("http", {}).get(field)
                if previous != current:
                    fields[f"http.{field}"] = {"before": previous, "after": current}
            for header in ("server", "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options"):
                def values(result):
                    return [item.get("value") for item in result.get("http", {}).get("headers", []) if item.get("name") == header]
                previous, current = values(old), values(new)
                if previous != current:
                    fields[f"http.headers.{header}"] = {"before": previous, "after": current}
            if not fields:
                continue
        changes.append({"address": key[0], "port": key[1], "transport": key[2], "kind": kind, "fields": fields})
    return {"schema_version": 1, "changes": changes, "change_count": len(changes)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--require-same-scope", action="store_true", help="reject changed endpoint scope (exit 2)")
    parser.add_argument("--fail-on-change", action="store_true", help="exit 1 if changes are found")
    args = parser.parse_args(argv)
    try:
        before, after = load_report(args.before), load_report(args.after)
        if args.require_same_scope and before.keys() != after.keys():
            raise ReportError("endpoint scope changed")
        result = compare(before, after)
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        print(f"astra-diff: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['change_count']} change(s)")
        for change in result["changes"]:
            # Escape untrusted strings before terminal output.
            endpoint = json.dumps(f"{change['address']}:{change['port']}/{change['transport']}", ensure_ascii=True)
            print(f"{endpoint} {change['kind']}")
            for field, values in change["fields"].items():
                print(f"  {field}: {json.dumps(values['before'])} -> {json.dumps(values['after'])}")
    return 1 if args.fail_on_change and result["changes"] else 0


if __name__ == "__main__":
    sys.exit(main())

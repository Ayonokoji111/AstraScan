#!/usr/bin/env python3
"""Compare complete AstraScan JSON inventories without third-party packages."""
import argparse
import json
import sys
from pathlib import Path


class ReportError(ValueError):
    pass


def load_report(path):
    with Path(path).open(encoding="utf-8") as stream:
        report = json.load(stream)
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ReportError(f"{path}: expected an AstraScan schema version 1 report")
    if report.get("scanner") != "AstraScan":
        raise ReportError(f"{path}: unexpected scanner")
    if report.get("cancelled") is not False or report.get("only_open") is not False:
        raise ReportError(f"{path}: diff requires a complete report without --open")
    if not isinstance(report.get("results"), list):
        raise ReportError(f"{path}: missing results")
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
        if not isinstance(address, str) or not address or type(port) is not int or not 1 <= port <= 65535 or transport != "tcp":
            raise ReportError(f"{path}: invalid endpoint")
        if result.get("state") not in {"open", "closed", "filtered", "error"}:
            raise ReportError(f"{path}: invalid state")
        if not isinstance(result.get("tls"), dict):
            raise ReportError(f"{path}: invalid TLS observation")
        key = (address, port, transport)
        if key in inventory:
            raise ReportError(f"{path}: duplicate endpoint")
        inventory[key] = result
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
            for field in ("handshake", "protocol", "cipher", "subject", "issuer", "not_after"):
                previous = old.get("tls", {}).get(field)
                current = new.get("tls", {}).get(field)
                if previous != current:
                    fields[f"tls.{field}"] = {"before": previous, "after": current}
            if not fields:
                continue
        changes.append({"address": key[0], "port": key[1], "transport": key[2], "kind": kind, "fields": fields})
    return {"schema_version": 1, "changes": changes, "change_count": len(changes)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on-change", action="store_true", help="exit 1 if changes are found")
    args = parser.parse_args(argv)
    try:
        result = compare(load_report(args.before), load_report(args.after))
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

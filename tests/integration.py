#!/usr/bin/env python3
"""Loopback-only integration tests. No external targets are contacted."""
import csv
import io
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

BINARY = str(Path(sys.argv[1]).resolve())
checks = 0
schema_validator = None
if os.environ.get("ASTRA_VALIDATE_SCHEMA") == "1":
    from jsonschema import Draft202012Validator, FormatChecker
    schema = json.loads((Path(__file__).resolve().parents[1] / "docs/report.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    schema_validator = Draft202012Validator(schema, format_checker=FormatChecker())


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(*args, code=0):
    proc = subprocess.run([BINARY, *map(str, args)], text=True, capture_output=True, timeout=15)
    check(proc.returncode == code, f"exit {proc.returncode}, expected {code}: {proc.stderr}")
    if schema_validator and proc.stdout.lstrip().startswith("{"):
        parsed = json.loads(proc.stdout)
        if parsed.get("scanner") == "AstraScan":
            schema_validator.validate(parsed)
    return proc.stdout


class Server:
    def __init__(self, response, ports=(0,), family=socket.AF_INET, context=None, read=False, delay=0):
        self.sock = socket.socket(family)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for port in ports:
            try:
                self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", port))
                break
            except OSError:
                if port == ports[-1]:
                    raise
        self.port = self.sock.getsockname()[1]
        self.sock.listen(64)
        self.sock.settimeout(0.1)
        self.response, self.context, self.read = response, context, read
        self.delay = delay
        self.stop = threading.Event()
        self.requests = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1)
                if self.delay:
                    time.sleep(self.delay)
                if self.context:
                    conn = self.context.wrap_socket(conn, server_side=True)
                if self.read:
                    self.requests.append(conn.recv(4096))
                for segment in self.response if isinstance(self.response, list) else [self.response]:
                    conn.sendall(segment)
                    if isinstance(self.response, list):
                        time.sleep(0.03)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


class UDPServer:
    def __init__(self, response=b"udp-fixture", family=socket.AF_INET):
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.1)
        self.stop = threading.Event()
        self.requests = []
        self.response = response
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                data, sender = self.sock.recvfrom(1024)
                self.requests.append(data)
                self.sock.sendto(self.response, sender)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(timeout=2)


servers = []
try:
    check("AstraScan" in run("--version"), "version")
    check("--dry-run" in run("--help"), "help")
    for args in [("127.0.0.1", "-p", "0"), ("127.0.0.1", "--workers", "0"), ("127.0.0.1", "--format", "yaml"), ("127.0.0.0/0", "--dry-run"), ("127.0.0.1", "--unknown"), ("127.0.0.1", "-p")]:
        run(*args, code=2)
    for args in [("--udp", "--http"), ("--udp-payload-hex", "01"), ("--udp", "--udp-payload-hex", "f"), ("--udp", "--udp-payload-hex", "gg"), ("--deadline", "0"), ("--http", "--server-name", "bad\r\nname")]:
        run("127.0.0.1", *args, code=2)
    plan = json.loads(run("127.0.0.1/30", "--exclude", "127.0.0.2/31", "--dry-run", "--format", "json", "-p", "22,80"))
    check(plan["tasks"] == 4, "CIDR/exclude plan")
    ssh = Server(b"SSH-2.0-LocalFixture\r\n"); servers.append(ssh)
    closed = socket.socket(); closed.bind(("127.0.0.1", 0)); closed_port = closed.getsockname()[1]
    report = json.loads(run("127.0.0.1", "-p", f"{ssh.port},{closed_port}", "--services", "--format", "json"))
    results = {r["port"]: r for r in report["results"]}
    check(report["schema_version"] == 2 and report["scope"]["transport"] == "tcp", "schema 2 scope manifest")
    check(results[ssh.port]["state"] == "open", "open TCP")
    check(results[ssh.port]["service"] == "ssh" and results[ssh.port]["service_source"] == "banner", "SSH evidence")
    check(results[closed_port]["state"] == "closed", "connection refused")
    check(report["completed"] == 2 and report["summary"]["open"] == 1, "summary counts")
    visible = json.loads(run("127.0.0.1", "-p", f"{ssh.port},{closed_port}", "--open", "--format", "json"))
    check(len(visible["results"]) == 1 and visible["completed"] == 2, "open filter preserves summary")
    http = Server(b'HTTP/1.0 200 OK\r\nServer: <script>alert(1)</script>\r\n\r\n', ports=(8080, 8000, 8888), read=True); servers.append(http)
    html = run("127.0.0.1", "-p", http.port, "--http", "--format", "html")
    check("&lt;script&gt;" in html and "<script>" not in html, "hostile banner escaped in HTML")
    check(http.requests and http.requests[0].startswith(b"HEAD / HTTP/1.0"), "HTTP HEAD")
    split = Server([b"HTTP/1.1 200 OK\r\nSer", b"ver: split-fixture\r\nX-Frame-Options: DENY\r\n", b"X-Content-Type-Options: nosniff\r\n\r\n"], read=True)
    servers.append(split)
    r = json.loads(run("127.0.0.1", "-p", split.port, "--http-ports", split.port, "--format", "json"))["results"][0]
    check(r["http"]["headers_complete"] and r["http"]["status"] == 200, "HTTP split-header assembly on custom port")
    check({h["name"]: h["value"] for h in r["http"]["headers"]}["server"] == "split-fixture", "HTTP normalized structured headers")
    silent = Server(b"HTTP/1.1 200 OK\r\nServer: partial", read=True); servers.append(silent)
    r = json.loads(run("127.0.0.1", "-p", silent.port, "--http-ports", silent.port, "--format", "json"))["results"][0]
    check(not r["http"]["headers_complete"], "incomplete HTTP response is explicit")
    oversized = Server(b"HTTP/1.1 200 OK\r\nX-Big: " + b"x" * 20000 + b"\r\n\r\n", read=True); servers.append(oversized)
    r = json.loads(run("127.0.0.1", "-p", oversized.port, "--http-ports", oversized.port, "--format", "json"))["results"][0]
    check(len(r["evidence"]) == 16384 and not r["http"]["headers_complete"], "HTTP hard read bound")
    slow = Server(b"HTTP/1.1 200 OK\r\n\r\n", read=True, delay=0.4); servers.append(slow)
    partial = json.loads(run("127.0.0.1", "-p", slow.port, "--http-ports", slow.port, "--timeout", "1000", "--deadline", "100", "--format", "json", code=124))
    check(partial["timed_out"] and partial["completed"] == 0, "deadline clips application read phase")
    udp = UDPServer(); servers.append(udp)
    r = json.loads(run("127.0.0.1", "--udp", "-p", udp.port, "--udp-payload-hex", "001bff", "--format", "json"))["results"][0]
    check(r["transport"] == "udp" and r["state"] == "open" and r["response_bytes"] == 11, "UDP response confirms open")
    check(udp.requests[-1] == b"\x00\x1b\xff", "UDP custom hex payload")
    zero = UDPServer(b""); servers.append(zero)
    r = json.loads(run("127.0.0.1", "--udp", "-p", zero.port, "--format", "json"))["results"][0]
    check(r["state"] == "open" and r["response_bytes"] == 0, "zero-length UDP reply confirms open")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unresponsive:
        unresponsive.bind(("127.0.0.1", 0))
        r = json.loads(run("127.0.0.1", "--udp", "-p", unresponsive.getsockname()[1], "--timeout", "50", "--retries", "1", "--format", "json"))["results"][0]
        check(r["state"] == "open|filtered" and r["attempts"] == 2, "UDP silence stays ambiguous with retries")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0)); udp_closed = reservation.getsockname()[1]
    r = json.loads(run("127.0.0.1", "--udp", "-p", udp_closed, "--format", "json"))["results"][0]
    check(r["state"] == "closed", "UDP ICMP refusal")
    csv_text = run("127.0.0.1", "-p", ssh.port, "--services", "--format", "csv")
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    check(rows[0]["evidence"].startswith("SSH-"), "CSV multiline evidence")
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "inventory.json"
        run("127.0.0.1", "-p", ssh.port, "--format", "json", "-o", output)
        check(json.loads(output.read_text())["completed"] == 1, "atomic file output")
        check(not list(Path(tmp).glob("*.tmp.*")), "no temporary files remain")
        targets = Path(tmp) / "targets.txt"
        targets.write_text("# loopback only\n127.0.0.1 127.0.0.1 # dedup\n")
        check(json.loads(run("-iL", targets, "--dry-run", "--format", "json"))["host_count"] == 1, "target file")
        if "OpenSSL" in run("--version"):
            cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=astra.local", "-days", "1", "-addext", "subjectAltName=DNS:astra.local,IP:127.0.0.1"], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
            tls = Server(b"HTTP/1.0 200 OK\r\nServer: tls-fixture\r\n\r\n", ports=(8443,), context=context, read=True); servers.append(tls)
            r = json.loads(run("127.0.0.1", "-p", tls.port, "--tls", "--http", "--timeout", "1500", "--format", "json"))["results"][0]
            check(r["tls"]["handshake"] and "astra.local" in r["tls"]["subject"], "TLS certificate metadata")
            check(r["tls"]["verified"] is False and r["tls"]["not_after"], "TLS trust explicit")
            check("tls-fixture" in r["evidence"], "HTTPS response")
            check(len(r["tls"]["sha256"]) == 64 and "DNS:astra.local" in r["tls"]["sans"] and "IP:127.0.0.1" in r["tls"]["sans"], "certificate SHA-256 and SANs")
            check(r["tls"]["sha256"] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest(), "fingerprint matches leaf DER bytes")
            trusted = json.loads(run("127.0.0.1", "-p", tls.port, "--tls", "--http", "--ca-file", cert, "--format", "json"))["results"][0]
            check(trusted["tls"]["verification_attempted"] and trusted["tls"]["verified"], "custom CA and IP identity verification")
            check(trusted["http"]["headers_complete"] and trusted["http"]["status"] == 200, "HTTPS structured headers")
            custom_tls = Server(b"HTTP/1.1 204 No Content\r\nServer: custom-tls\r\n\r\n", context=context, read=True); servers.append(custom_tls)
            trusted = json.loads(run("127.0.0.1", "-p", custom_tls.port, "--tls-ports", custom_tls.port, "--http-ports", custom_tls.port, "--server-name", "astra.local", "--ca-file", cert, "--format", "json"))["results"][0]
            check(trusted["tls"]["verified"] and trusted["http"]["status"] == 204, "custom TLS/HTTP ports and DNS identity")
            wrong = json.loads(run("127.0.0.1", "-p", tls.port, "--tls", "--http", "--ca-file", cert, "--server-name", "wrong.local", "--format", "json"))["results"][0]
            check(wrong["state"] == "open" and not wrong["tls"]["verified"] and wrong["tls"]["verification_error"], "hostname mismatch preserves TCP evidence")
            untrusted = json.loads(run("127.0.0.1", "-p", tls.port, "--verify-tls", "--http", "--format", "json"))["results"][0]
            check(untrusted["tls"]["verification_attempted"] and not untrusted["tls"]["verified"], "untrusted self-signed certificate is rejected")
            delayed_tls = Server(b"", delay=0.4); servers.append(delayed_tls)
            partial = json.loads(run("127.0.0.1", "-p", delayed_tls.port, "--tls-ports", delayed_tls.port, "--timeout", "1000", "--deadline", "100", "--format", "json", code=124))
            check(partial["timed_out"] and partial["completed"] == 0, "deadline clips TLS handshake phase")
            run("127.0.0.1", "--ca-file", Path(tmp) / "missing.pem", code=2)
        else:
            run("127.0.0.1", "--tls", code=2)
    try:
        v6 = Server(b"SSH-2.0-IPv6\r\n", family=socket.AF_INET6); servers.append(v6)
    except OSError:
        print("SKIP: IPv6 loopback unavailable")
    else:
        r = json.loads(run("::1", "-p", v6.port, "--services", "--format", "json"))["results"][0]
        check(r["address"] == "::1" and r["state"] == "open", "IPv6 connect")
        udp6 = UDPServer(family=socket.AF_INET6); servers.append(udp6)
        r = json.loads(run("::1", "--udp", "-p", udp6.port, "--format", "json"))["results"][0]
        check(r["address"] == "::1" and r["state"] == "open" and r["transport"] == "udp", "IPv6 UDP response")
    started = time.monotonic()
    partial = json.loads(run("127.0.0.1", "-p", "1-100", "--rate", "1", "--workers", "8", "--deadline", "120", "--format", "json", code=124))
    check(partial["timed_out"] and not partial["cancelled"] and partial["completed"] < partial["planned"], "deadline produces explicit partial report")
    check(time.monotonic() - started < 2, "deadline interrupts rate limiter")
    start = time.monotonic()
    run("127.0.0.1", "-p", "1-5", "--rate", "5", "--workers", "5", "--timeout", "50", "--format", "json")
    check(time.monotonic() - start >= 0.74, "global rate limiter")
    proc = subprocess.Popen([BINARY, "127.0.0.1", "-p", "1-100", "--rate", "1", "--workers", "2", "--format", "json"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.3); proc.send_signal(signal.SIGINT)
    stdout, stderr = proc.communicate(timeout=5)
    partial = json.loads(stdout)
    check(proc.returncode == 130 and partial["cancelled"] and partial["completed"] < partial["planned"], "cancellation partial report")
    # Saturate a local accept queue to produce a real connect timeout without external traffic.
    backlog = socket.socket()
    backlog.bind(("127.0.0.1", 0))
    backlog.listen(0)
    filler = socket.create_connection(backlog.getsockname(), timeout=1)
    try:
        r = json.loads(run("127.0.0.1", "-p", backlog.getsockname()[1], "--timeout", "100", "--retries", "1", "--format", "json"))["results"][0]
        check(r["state"] == "filtered" and r["attempts"] == 2, "timeout and retry on saturated loopback queue")
    finally:
        filler.close()
        backlog.close()
    with tempfile.TemporaryDirectory() as tmp:
        inventory = Path(tmp) / "inventory.json"
        policy_file = Path(tmp) / "policy.json"
        raw = run("127.0.0.1", "-p", split.port, "--http-ports", split.port, "--format", "json")
        inventory.write_text(raw)
        root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, str(root / "tools/astra-diff.py"), str(inventory), str(inventory), "--require-same-scope", "--fail-on-change"], check=True, capture_output=True)
        policy_file.write_text(json.dumps({"schema_version": 1, "required_scope": [{"address": "127.0.0.1", "ports": [split.port]}], "rules": [{"network": "127.0.0.1/32", "allow_ports": [split.port], "http_ports": [split.port], "require_http_headers": ["x-content-type-options"]}]}))
        subprocess.run([sys.executable, str(root / "tools/astra-policy.py"), str(inventory), str(policy_file)], check=True, capture_output=True)
        check(True, "schema 2 diff/policy generated-report end-to-end")
    closed.close()
    print(f"{checks} integration checks passed (loopback only)")
finally:
    for server in servers:
        server.close()

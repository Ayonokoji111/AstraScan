#!/usr/bin/env python3
"""Loopback-only integration tests. No external targets are contacted."""
import csv
import io
import json
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


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


def run(*args, code=0):
    proc = subprocess.run([BINARY, *map(str, args)], text=True, capture_output=True, timeout=15)
    check(proc.returncode == code, f"exit {proc.returncode}, expected {code}: {proc.stderr}")
    return proc.stdout


class Server:
    def __init__(self, response, ports=(0,), family=socket.AF_INET, context=None, read=False):
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
                if self.context:
                    conn = self.context.wrap_socket(conn, server_side=True)
                if self.read:
                    self.requests.append(conn.recv(4096))
                conn.sendall(self.response)
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

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
    plan = json.loads(run("127.0.0.1/30", "--exclude", "127.0.0.2/31", "--dry-run", "--format", "json", "-p", "22,80"))
    check(plan["tasks"] == 4, "CIDR/exclude plan")
    ssh = Server(b"SSH-2.0-LocalFixture\r\n"); servers.append(ssh)
    closed = socket.socket(); closed.bind(("127.0.0.1", 0)); closed_port = closed.getsockname()[1]
    report = json.loads(run("127.0.0.1", "-p", f"{ssh.port},{closed_port}", "--services", "--format", "json"))
    results = {r["port"]: r for r in report["results"]}
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
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=astra.local", "-days", "1"], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
            tls = Server(b"HTTP/1.0 200 OK\r\nServer: tls-fixture\r\n\r\n", ports=(8443,), context=context, read=True); servers.append(tls)
            r = json.loads(run("127.0.0.1", "-p", tls.port, "--tls", "--http", "--timeout", "1500", "--format", "json"))["results"][0]
            check(r["tls"]["handshake"] and "astra.local" in r["tls"]["subject"], "TLS certificate metadata")
            check(r["tls"]["verified"] is False and r["tls"]["not_after"], "TLS trust explicit")
            check("tls-fixture" in r["evidence"], "HTTPS response")
        else:
            run("127.0.0.1", "--tls", code=2)
    try:
        v6 = Server(b"SSH-2.0-IPv6\r\n", family=socket.AF_INET6); servers.append(v6)
    except OSError:
        print("SKIP: IPv6 loopback unavailable")
    else:
        r = json.loads(run("::1", "-p", v6.port, "--services", "--format", "json"))["results"][0]
        check(r["address"] == "::1" and r["state"] == "open", "IPv6 connect")
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
    closed.close()
    print(f"{checks} integration checks passed (loopback only)")
finally:
    for server in servers:
        server.close()

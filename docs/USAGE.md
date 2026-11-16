# Usage reference

## Scope

Pass one or more hostnames, numeric IPv4 addresses, IPv6 addresses, or IPv4 CIDRs. Every address in a CIDR is included, including network and broadcast addresses; the scanner does not assume these are unusable. IPv6 literals are passed without URL brackets. IPv6 zone IDs are supported when the local interface or numeric scope ID exists. IPv6 CIDR expansion is not supported.

Hostname resolution uses the system resolver and includes all returned IPv4/IPv6 addresses. Duplicate numeric addresses are scanned once; the first target label wins. No reverse DNS lookup is performed. DNS resolution occurs even during a dry run and has the system resolver's timeout behavior, not `--timeout`. Resolution failures abort the scan before connections start. Exclusion hostnames are resolved too.

```bash
./build/astrascan localhost 127.0.0.1 ::1 -p 22,80 --dry-run --format json
./build/astrascan 192.168.1.0/28 --exclude 192.168.1.5/32 -p 22,443
./build/astrascan --target-file targets.txt --exclude-file exclusions.txt -p 1-1024
```

List files accept whitespace-separated tokens and `#` comments. Limits default to 4096 resolved hosts and an absolute maximum of 1,000,000 host/port tasks. `--max-hosts` accepts up to 65536, but a single CIDR is checked against that cap before exclusions. Split larger scopes into smaller runs. No background discovery, ping, ARP sweep, or public target selection is performed.

## Ports and tuning

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--ports` | 26 common TCP ports | Comma-separated ports and inclusive ranges; deduplicated and sorted |
| `--all-ports` | Off | TCP ports 1–65535 |
| `--workers` | 64 | Simultaneous endpoint tasks; range 1–512 |
| `--rate` | 200 | Maximum global TCP connection starts/second; retries count too |
| `--timeout` | 700 ms | Per-connect and per-probe phase deadline; range 10–60000 |
| `--retries` | 0 | Extra attempts on timeouts/network errors; range 0–5 |
| `--max-hosts` | 4096 | Scope expansion cap |

The default ports are 21,22,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017. These are a curated list, not a measured top-port ranking. When repeated, the last `--ports` / `--all-ports` option wins.

Rate limiting spaces connection starts; it does not limit all packets or bandwidth. TLS/HTTP probes run within their worker after an open connection. A task can take multiple timeout phases, particularly with retries. Blocking DNS resolution and filesystem writes are outside probe deadlines. `latency_ms` measures the final TCP connection attempt, not total task duration or application response time. A lower worker count may help avoid file descriptor limits.

## Service probes

- `--services` reads one passive response of at most 2048 bytes. It recognizes SSH (`SSH-`), HTTP (`HTTP/`), and VNC (`RFB `) prefixes. It does not actively request versions from databases or other protocols.
- `--http` sends `HEAD / HTTP/1.0` on 80, 8000, 8080, 8888, and 9200. `--tls --http` additionally sends HEAD after a successful TLS handshake on 443 and 8443.
- `--tls` attempts a TLS handshake on 443, 8443, 465, 636, 993, and 995. It collects negotiated protocol/cipher and peer certificate metadata. No STARTTLS upgrade, SAN extraction, chain verification, hostname validation, or vulnerability assessment is implemented.

TLS certificates are **not authenticated**: `tls.verified` is always false. A successful handshake proves only that a TLS session was negotiated. An open port remains `open` if a subsequent TLS/application probe fails; a TLS failure is recorded in `error`. Passive banners may be empty without implying an error. HTTP response headers may be truncated. Remote binary/control bytes are replaced with dots. HTTP HEAD can be logged and may have application side effects on misconfigured services.

Service names without a recognized prefix are guesses based on port number, even for closed ports. JSON `service_source` distinguishes `banner` and `port_hint`. TLS protocol/cipher metadata is separate from service recognition.

## States and exit status

| State | Meaning |
| --- | --- |
| `open` | The operating system completed a TCP connection |
| `closed` | The connection was explicitly refused |
| `filtered` | The connect attempt reached its timeout; filtering is only one possible cause |
| `error` | Another failure, such as an unreachable route or local socket exhaustion |

`filtered` is inconclusive: an offline host, packet loss, or a slow network can also cause it. A refused connection can originate from an intermediary. There is no host-up/down claim.

| Exit | Scanner | Diff | Policy |
| --- | --- | --- | --- |
| 0 | Completed without `error` states; closed/filtered are allowed | Successful comparison; or no changes with `--fail-on-change` | No violations in scanned endpoints |
| 1 | At least one endpoint has `error` state | Changes found with `--fail-on-change` | Policy violations / inconclusive endpoints |
| 2 | Invalid arguments, resolution failure, or report-write failure | Invalid/incomplete report or I/O failure | Invalid report/policy or I/O failure |
| 130 | Interrupted scan; partial report written if possible | — | — |

SIGINT and SIGTERM stop new work and interrupt socket waits. Workers finish cancellation promptly, then the scanner emits finalized results. A task interrupted during a probe may be omitted even if the TCP connection had succeeded. Atomic output replacement uses a temporary file in the destination directory, restrictive permissions, file fsync, and rename. It does not promise directory-level crash durability. Existing output files are replaced.

## Reports

`--format text|json|csv|html` selects output; `-o FILE` writes a file instead of stdout. `--open` filters displayed rows but leaves counts intact. JSON records `only_open` so consumers can detect filtered evidence. Ordering is numeric-address **lexicographic**, then ascending port; it is deterministic, not numeric IP ordering.

Dry run emits a JSON plan with `--format json`; all other format choices yield a plain-text plan. The dry-run object is not a scan report and cannot be diffed or policy-checked.

CSV quotes fields and prefixes potentially executable spreadsheet cells with an apostrophe. HTML escapes remote content, disables external resources and scripts with a CSP, and has no network dependencies. Inventory and certificate information may still be sensitive; reports are ignored by Git by default.

## Policies and CI

```bash
./build/astrascan 127.0.0.1 -p 22,80,443 --tls --format json -o inventory.json
python3 tools/astra-policy.py inventory.json docs/policy.example.json
```

A policy is a JSON object with `schema_version: 1` and a nonempty `rules` array. See [the example](policy.example.json). Each rule supports:

- `network`: canonical IPv4/IPv6 CIDR.
- `allow_ports`: permitted open TCP ports. Missing/empty means no open ports permitted.
- `require_tls_ports`: open ports that must have a successful TLS handshake and parseable certificate expiration. Invoke the scanner with `--tls`; only its supported TLS ports can satisfy this requirement.
- `min_cert_days`: minimum remaining certificate lifetime for `require_tls_ports`, default zero. Uses UTC.

The most specific network rule wins. For equal prefix lengths, the first matching rule wins. Unmatched open endpoints are violations. Closed endpoints pass regardless of policy. Filtered/error endpoints fail as inconclusive. Required TLS ports are not required to be open; this is an exposure policy, not an availability monitor. Trust verification is not performed, so this must not be used as a certificate trust gate.

**Policy coverage is only the report's scanned endpoints.** An omitted host or port is not evaluated. Scope additions/removals can be reviewed with `astra-diff`, which reports `scope_added` / `scope_removed` separately from changed observations. Use stable target/port scope in CI and inspect DNS-induced scope changes. The helpers reject empty inventories. Neither helper authenticates report provenance.

## Installation

```bash
make
sudo make install
astrascan --version
astra-diff before.json after.json
astra-policy inventory.json /path/to/policy.json
```

`make install` uses GNU `install` and defaults to `/usr/local`. Use `PREFIX=/custom/path` or `DESTDIR=/staging/path` when packaging. CMake installation is also supported. Keep the two Python helpers together; the policy helper shares the diff helper's report loader. Helpers require Python 3.9+ in PATH.

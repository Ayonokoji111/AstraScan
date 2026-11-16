# Usage reference

## Scope

Targets may be hostnames, numeric IPv4/IPv6 addresses, or IPv4 CIDRs. Every address in a CIDR is included, including network and broadcast addresses. IPv6 CIDRs are unsupported; IPv6 literals do not use URL brackets. Local IPv6 interface/numeric zone IDs are supported.

System DNS resolves all IPv4/IPv6 addresses before scan connections start, including in dry runs. No reverse DNS is performed. Exclusion hostnames are also resolved. Duplicate numeric addresses are scanned once; the first target label wins. DNS errors abort before scanning. DNS uses the system resolver's deadlines, not scanner timeout/deadline flags.

```bash
./build/astrascan localhost 127.0.0.1 ::1 -p 22,80 --dry-run --format json
./build/astrascan 192.168.1.0/28 --exclude 192.168.1.5/32 -p 22,443
./build/astrascan -iL targets.txt --exclude-file exclusions.txt -p 1-1024
```

List files accept whitespace-separated tokens and `#` comments. The default expansion cap is 4096 addresses; `--max-hosts` accepts 1–65536. A CIDR is checked against the cap **before** exclusions. The absolute host/port task cap is 1,000,000. Split larger scopes. The scanner performs no implicit public-target selection, ping, ARP discovery, or reverse DNS.

## Ports and tuning

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--ports` | Common ports for selected transport | Sorted, deduplicated ports/ranges |
| `--all-ports` | Off | Ports 1–65535 for selected transport |
| `--udp` | Off | Select UDP instead of TCP for the whole invocation |
| `--workers` | 64 | Simultaneous endpoint tasks, 1–512 |
| `--rate` | 200 | Global maximum attempt starts/second, including retries |
| `--timeout` | 700 ms | Per-connect/probe phase deadline, 10–60000 |
| `--retries` | 0 | Additional timeout/network-error attempts, 0–5 |
| `--deadline` | Disabled | Overall scan deadline in ms, 1–86400000 |
| `--max-hosts` | 4096 | Address expansion cap |

Default TCP ports: 21,22,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017. Default UDP ports: 53,123,161,500,1900,4500,5353. These are curated lists, not measured popularity rankings. The last `-p` / `--all-ports` wins.

Rate limiting spaces attempt starts, not all packets or bandwidth. A TCP task can include several probe phases. Refused connections are not retried. TLS/HTTP failures after an open TCP connection are not retried. TCP `latency_ms` measures the final connection attempt; UDP measures connection setup plus final response wait. Neither is an application benchmark.

The overall deadline starts after DNS and clips scheduling/socket waits, including rate-limit sleeps. Deadline expiry emits finalized results with `timed_out: true`, then exits 124. It is not a hard CPU/OS kill: local CA-file loading, certificate verification CPU time, and output writes cannot be preempted by socket deadlines. SIGINT/SIGTERM stop new work and waits, then write partial results with exit 130. An interrupted task may be omitted even if its TCP connection succeeded.

## UDP observations

```bash
./build/astrascan 127.0.0.1 --udp -p 53,123 --timeout 500 --retries 1
./build/astrascan 127.0.0.1 --udp -p 9999 --udp-payload-hex 41535452 --format json
```

The default UDP probe is a **zero-length datagram**. `--udp-payload-hex` supplies an even-length hexadecimal string of at most 512 bytes. No protocol-specific query is generated automatically. Use a payload appropriate for the service you control when a response is needed. A service that ignores empty/unknown packets will remain inconclusive.

A datagram reply, including an empty datagram, confirms `open`. A connected UDP socket's explicit `ECONNREFUSED` response is `closed`. Silence is **`open|filtered`**, never proof of openness or filtering. Other network/socket errors are `error`. No raw ICMP packet interpretation is performed; behavior depends on the OS's connected UDP socket errors. ICMP rate limiting can increase ambiguity. Evidence reads at most 2048 bytes of a datagram; `response_bytes` is the captured count, not the original length if truncated.

TCP banner, HTTP, TLS, and server-name options cannot be combined with UDP mode. TCP and UDP inventories are separate runs. The policy checker distinguishes transport allowlists; inconclusive UDP observations fail policy evaluation.

## Service and HTTP inspection

- `--services` reads a passive banner up to 2048 bytes. SSH (`SSH-`), HTTP (`HTTP/`), and VNC (`RFB `) prefixes can confirm a service label. Other labels remain `port_hint`, including labels on closed ports. This is not broad version detection.
- `--http` sends `HEAD / HTTP/1.0` on 80,8000,8080,8888,9200. With TLS enabled, it also probes 443/8443 after a TLS handshake.
- `--http-ports LIST` replaces the HTTP probe port set and enables HTTP. `--tls-ports LIST` replaces the TLS set and enables TLS. Neither changes the scan port set; use `-p` too.
- `--server-name NAME` overrides TLS SNI/verification identity and HTTP Host for **every target** in that invocation. It does not change DNS resolution or target IPs. Use single-service scopes with this option. IPv6 HTTP Host values are bracketed, and nonstandard ports are included.

HTTP reads assemble split headers up to **16384 bytes** under one absolute read deadline. Reports record status, normalized lowercase header names, repeated header entries in order, and `headers_complete`. Partial trailing fields are ignored. Complete evidence is truncated at the end of headers. The parser handles HTTP/1.0 and HTTP/1.1; it does not follow redirects, negotiate HTTP/2, parse response bodies, or advance through informational responses. It reports the first observed response. HEAD may be logged and can have side effects on misconfigured applications.

Remote control/non-ASCII bytes become dots. Passive banners may be absent without implying failure. HTTP headers can expose sensitive tokens/cookies and are not redacted automatically. Treat inventories as sensitive.

## TLS and certificate trust

Default TLS ports: 443,8443,465,636,993,995. There is no STARTTLS upgrade. OpenSSL 3 is required; no-TLS builds reject TLS flags.

```bash
./build/astrascan example.test -p 443 --verify-tls --http --format json
./build/astrascan 127.0.0.1 -p 9443 --tls-ports 9443 --http-ports 9443 \
  --server-name app.example.test --ca-file ./local-ca.pem --format json
```

TLS collection reports negotiated protocol/cipher, certificate subject, issuer, expiration, lowercase SHA-256 fingerprint of the leaf DER certificate, and at most 128 DNS/IP SAN entries. Each DNS SAN is bounded to 253 bytes. SANs describe the certificate; they are not new scan targets.

`--tls` collects metadata without trust verification. `--verify-tls` additionally checks the leaf and presented intermediates against system CA roots, server certificate purpose/time validity, and the target DNS/IP identity. DNS matching uses OpenSSL with partial wildcards disabled. Numeric targets use IP SAN matching, unless `--server-name` overrides the identity. `--ca-file` enables verification using the specified PEM trust bundle **instead of** default roots. The CA-file path and contents are not embedded in the report.

Verification occurs after the observational handshake so invalid certificates can still be inventoried. `verification_attempted` and `verified` distinguish disabled checks, verified trust, and failed trust; `verification_error` explains failure. A failed handshake means no verification was attempted. Failures preserve the open TCP state, so scanner exit 0 does **not** guarantee TLS trust. Use `require_verified_tls_ports` in a policy to enforce it.

There is no online revocation check, OCSP, certificate transparency validation, automatic AIA/intermediate download, cipher-strength audit, or vulnerability assessment. Verification reflects the selected local trust bundle and scan time, not an unconditional security guarantee.

## States and exit status

| State | Interpretation |
| --- | --- |
| `open` | TCP connection succeeded, or a UDP reply was received |
| `closed` | Explicit connection refusal; an intermediary may be responsible |
| `filtered` | TCP connect timeout; filtering, packet loss, offline host, or latency may explain it |
| `open\|filtered` | UDP response timeout; open service and filtering cannot be distinguished |
| `error` | Another network or local socket failure |

| Exit | Scanner | Diff | Policy |
| --- | --- | --- | --- |
| 0 | Completed, no endpoint `error`; other states/failed TLS verification are allowed | Compared successfully; or no changes with `--fail-on-change` | No policy violations |
| 1 | At least one endpoint `error` | Changes with `--fail-on-change` | Violations / inconclusive results |
| 2 | Invalid input, DNS/config failure, or write failure | Invalid report / changed scope with scope guard | Invalid report/policy or I/O failure |
| 124 | Deadline-truncated report | — | — |
| 130 | Interrupted report | — | — |

## Reports and diffs

`--format text|json|csv|html` selects output, and `-o FILE` writes it. Existing files are replaced atomically through a private temporary file, file fsync, and same-directory rename. Directory-level crash durability is not promised. `--open` filters rows but not summary counts; helpers reject these filtered inventories.

JSON schema **2** includes transport, finalized counts, cancellation/deadline flags, resolved scope addresses/ports, configuration/probe settings, trust checks, HTTP details, and evidence. Schema-1 reports from 0.1 remain readable by the updated helpers. Old helpers cannot read v2; see [migration](MIGRATION.md). `--dry-run --format json` emits a distinct scope plan; other dry-run formats use plain text. A plan is not a scan report.

Output order is lexicographic by numeric address string, then port. JSON strings are ASCII-oriented, not lossless Unicode/binary forensic capture. CSV escapes cells and formula prefixes. HTML escapes evidence, uses a restrictive CSP, and loads no external resources.

```bash
python3 tools/astra-diff.py before.json after.json --format json
python3 tools/astra-diff.py before.json after.json --require-same-scope --fail-on-change
```

Diffs compare state/service; certificate handshake, protocol, cipher, identity, expiry, verification state, fingerprint and SANs; HTTP status/completeness; and `server`, `strict-transport-security`, `content-security-policy`, `x-content-type-options`, `x-frame-options` headers. Date/timing/banner noise is ignored. Scope additions/removals are separate observations. `--require-same-scope` rejects any endpoint-scope difference with exit 2. Keep probe settings consistent too; a newly enabled probe can appear as a metadata change. Helpers do not authenticate report provenance.

## Policies and CI

Policy JSON retains `schema_version: 1`. A nonempty `rules` array contains:

- `network`: canonical IPv4/IPv6 CIDR. Most specific rule wins; equal prefixes use the first rule.
- `allow_ports`: allowed **TCP** open ports; missing means none.
- `allow_udp_ports`: allowed **UDP** open ports; missing means none.
- `require_tls_ports`: open TCP ports requiring a TLS handshake and parseable expiration.
- `require_verified_tls_ports`: open TCP ports requiring a handshake, attempted/successful chain and identity verification, and parseable expiration. Use the scanner's verification flags.
- `min_cert_days`: minimum certificate lifetime for either TLS requirement, default 0.
- `http_ports`: open TCP ports requiring a complete, recognized HTTP response.
- `require_http_headers`: lowercase names requiring nonempty values on `http_ports`. This checks presence only; values are not semantically audited.

Closed endpoints pass exposure checks. Unmatched open endpoints fail. Filtered/error/ambiguous UDP endpoints fail as inconclusive. Required TLS/HTTP ports are **not required to be open**; this is an exposure policy, not an availability monitor.

Top-level `required_scope` optionally lists exact mandatory addresses/ports/transports:

```json
{
  "schema_version": 1,
  "required_scope": [
    {"address": "127.0.0.1", "ports": [22, 80, 443], "transport": "tcp"}
  ],
  "rules": [
    {
      "network": "127.0.0.1/32",
      "allow_ports": [22, 80, 443],
      "require_verified_tls_ports": [443],
      "min_cert_days": 14,
      "http_ports": [80, 443],
      "require_http_headers": ["x-content-type-options"]
    }
  ]
}
```

A mandatory endpoint absent from the report fails as `required_endpoint_not_scanned`; TCP and UDP coverage are distinct. Equivalent IPv6 spellings are normalized. Without required coverage, policies still apply only to scanned endpoints. The schema-2 scope manifest is checked against complete result coverage by the helpers, but a forged report remains forgeable.

The provided [TCP policy](policy.example.json) and [UDP policy](policy-udp.example.json) are examples; customize them before use. Run TCP and UDP policy checks separately. Expiry policy uses UTC; no TLS trust requirement is inferred from a handshake-only rule.

## Installation

```bash
make
sudo make install
astrascan --version
astra-diff before.json after.json
astra-policy inventory.json /path/to/policy.json
```

GNU `install` defaults to `/usr/local`. Override `PREFIX` or stage with `DESTDIR`. CMake installation is supported. Keep both Python helpers together because the policy tool shares the diff loader. Helpers require Python 3.9+ in PATH. A staged install is tested in CI.

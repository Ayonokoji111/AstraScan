# AstraScan

**C++20 TCP/UDP inventory, verified TLS inspection, structured HTTP evidence, and CI exposure policies.**

AstraScan is an original, Nmap-inspired project for repeatable network inventories on systems you are authorized to assess. Its workflow is **preview → scan → save JSON → compare → enforce coverage and exposure policy**.

Version **0.2.0** adds UDP observation, certificate trust and identity checks, SHA-256 certificate fingerprints, SANs, custom probe ports, bounded HTTP header assembly, scan deadlines, scope manifests, and stronger CI policy checks.

This remains an early project. It does not replace Nmap's mature service signatures, raw SYN scans, OS fingerprinting, host discovery, or scripting engine. No performance or accuracy superiority over Nmap has been demonstrated. No Nmap source or signature database is included.

## Features

- **IPv4/IPv6 TCP connect scans** and **UDP scans** without raw-socket privileges. UDP replies confirm `open`, connection refusal yields `closed`, and silence remains `open|filtered`.
- **Hostnames, IPv4 CIDR, target/exclusion files, deduplication, scope limits**, and a dry-run preview.
- **Bounded concurrency**, global attempt-start rate limiting, per-phase timeouts, retries, and an overall scan deadline.
- **Passive SSH, HTTP, and VNC prefix recognition** with explicit evidence sources; other names are port hints.
- **HTTP/HTTPS HEAD**, custom probe ports, split-header assembly, status, normalized duplicate-preserving headers, completeness flags, and a 16 KiB read limit.
- **TLS protocol/cipher, certificate SHA-256, DNS/IP SANs, subject/issuer/expiration**. Optional chain, server-purpose, and DNS/IP identity verification against system roots or a PEM CA bundle.
- **Text, JSON, CSV, and standalone HTML** reports with context-specific escaping, formula neutralization, and atomic private output files.
- **Cancellation and deadline partial reports**, deterministic ordering, explicit scope/configuration metadata, and documented exit codes.
- **Inventory diffs** for transport/state, TLS trust/fingerprint/SAN changes, HTTP status and selected stable headers. Optional scope guard for CI.
- **Policies** for expected endpoint coverage, separate TCP/UDP allowlists, verified TLS, certificate lifetime, and required HTTP header presence. Inconclusive observations fail policy checks.
- **Make/CMake**, tests against local fixtures, sanitizer checks, and GitHub Actions. Python helpers use only the standard library.

## Quick start

Tested platform: Linux, C++20, OpenSSL 3, Python 3.9+. GitHub CI exercises GCC, Clang, no-TLS builds, and sanitizers. Windows is unsupported; macOS has not been validated.

```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev python3 openssl

git clone https://github.com/Ayonokoji111/AstraScan.git
cd AstraScan
make -j2
make test

./build/astrascan 127.0.0.1 -p 22,80,443 --dry-run
./build/astrascan 127.0.0.1 -p 22,80,443 --services --tls --http
```

Use a separate directory for build variants: `make TLS=0 BUILD=build-no-tls test`. A no-TLS build rejects TLS flags.

CMake alternative (3.20+):

```bash
cmake -S . -B build-cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build-cmake -j2
ctest --test-dir build-cmake --output-on-failure
```

## Advanced inspection

```bash
mkdir -p reports

# Inspect a service on a nonstandard port, connecting to an IP while using
# its actual DNS identity for SNI, HTTP Host, and certificate verification.
./build/astrascan 127.0.0.1 -p 9443 \
  --tls-ports 9443 --http-ports 9443 --server-name app.example.test \
  --ca-file ./local-ca.pem --format json -o reports/tls.json

# A UDP timeout is deliberately inconclusive. Default payload is empty.
./build/astrascan 127.0.0.1 --udp -p 53,123 --timeout 500 --format json

# Bound the scan's network scheduling/socket phases to five seconds.
./build/astrascan 127.0.0.1 -p 1-65535 --deadline 5000 \
  --format json -o reports/partial.json
# Exit 124 means the deadline ended an incomplete scan.
```

`--tls-ports` / `--http-ports` choose **probe** ports; `-p` chooses **scan** ports. TLS observation defaults to trust **not checked**. `--verify-tls` enables chain and identity verification; `--ca-file` also enables it. Verification failure preserves the open TCP observation and is enforced by the policy helper when requested. Revocation and certificate transparency are not checked.

## Inventory and policy workflow

```bash
./build/astrascan 127.0.0.1 -p 22,80,443 --tls --verify-tls --http \
  --format json -o reports/before.json
# Repeat with the same scope and probe settings later:
./build/astrascan 127.0.0.1 -p 22,80,443 --tls --verify-tls --http \
  --format json -o reports/after.json

python3 tools/astra-diff.py reports/before.json reports/after.json \
  --require-same-scope --fail-on-change
python3 tools/astra-policy.py reports/after.json docs/policy.example.json

./build/astrascan 127.0.0.1 -p 22,80,443 --tls --http \
  --format html -o reports/scan.html
```

Edit the example policy for your environment. The helpers reject incomplete reports and `--open` output. `required_scope` prevents a policy pass when mandatory endpoints were never scanned. Required HTTP headers are checked for **nonempty presence**, not correctness of their values or proof of application security. See [policy semantics](docs/USAGE.md#policies-and-ci).

## Relationship to Nmap

| Capability | AstraScan 0.2 | Nmap |
| --- | --- | --- |
| Unprivileged TCP / IPv4 / IPv6 | Yes | Yes |
| UDP | Generic bounded datagrams, ICMP refusal, explicit ambiguity | Mature UDP scanning and protocol probes |
| Service identification | Small port map + SSH/HTTP/VNC prefix recognition | Extensive signatures and probes |
| TLS / HTTP inspection | Built in, including optional certificate trust verification | Available through scripts |
| Raw SYN / OS fingerprinting / NSE / discovery | Not implemented | Available |
| JSON / self-contained HTML | Built in | Other formats, conversions available |
| Inventory diff / CI coverage + exposure policies | Bundled Python helpers | Ndiff, scripts, and other tooling |

## Documentation

- [CLI, probes, states, limits, policies, and installation](docs/USAGE.md)
- [Architecture and runtime contracts](docs/ARCHITECTURE.md)
- [JSON schema v2](docs/report.schema.json) and [migration notes](docs/MIGRATION.md)
- [Development](CONTRIBUTING.md), [security](SECURITY.md), [changelog](CHANGELOG.md), [roadmap](docs/ROADMAP.md)

Run `./build/astrascan --help` for flags. Licensed under [MIT](LICENSE); OpenSSL is provided by the system under its own license.

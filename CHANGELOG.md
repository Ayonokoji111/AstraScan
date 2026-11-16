# Changelog

## 0.2.0 — 2026-11-16

- Added bounded IPv4/IPv6 UDP scans with optional hex payloads, explicit refusal handling, and honest `open|filtered` timeouts.
- Added overall scan deadlines, partial-report metadata, and exit 124.
- Added TLS certificate chain/server-purpose/hostname or IP verification against system roots or a custom CA file.
- Added leaf SHA-256 fingerprints, DNS/IP SANs, custom TLS/HTTP probe ports, and explicit server identity overrides.
- Added bounded split HTTP header assembly, structured status/headers, duplicate preservation, and completeness flags.
- Introduced JSON schema 2 with resolved scope and configuration manifests; updated helpers retain schema-1 input support.
- Expanded policies with required coverage, UDP allowlists, verified TLS, and HTTP header requirements.
- Expanded diffs with certificate/trust/HTTP changes and a scope-equality guard.
- Added local fixtures and regression coverage for the new behavior; upgraded the pinned checkout action to v6.

## 0.1.0 — 2026-11-16

Initial public release:

- C++20 IPv4/IPv6 TCP connect scanner with bounded workers and global connection-start rate limits.
- Target files, IPv4 CIDR, deduplication, exclusion files, and scope previews.
- Passive SSH/HTTP/VNC prefix recognition, HTTP HEAD, and optional OpenSSL 3 TLS metadata.
- Text/JSON/CSV/HTML output with bounded evidence and output escaping.
- Atomic output files, signal cancellation, partial-report metadata, and stable exit codes.
- Python inventory diff and CIDR exposure policies with certificate-expiration thresholds.
- Make/CMake builds, local integration tests, CI configuration, docs, MIT license, and contribution templates.

Known limitations are documented in README.md and docs/USAGE.md. This release makes no performance or accuracy superiority claim over Nmap.

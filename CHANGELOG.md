# Changelog

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

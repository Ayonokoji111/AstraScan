# Migrating from 0.1 to 0.2

## CLI

Existing TCP flags retain their behavior. TCP remains the default transport. UDP is an explicit separate invocation. Custom HTTP/TLS port flags select probe ports, not the actual scan set. `--deadline` can now yield exit 124 and a partial report; scripts must handle it alongside exit 130.

TLS metadata is still observational unless `--verify-tls` or `--ca-file` enables verification. Consumers should use `verification_attempted` as well as `verified`. A failed trust check leaves an open TCP endpoint open. Use the policy helper for a trust gate.

## JSON schema 2

New scanner reports use schema version 2. Older reports remain described by [schema 1](report-v1.schema.json). Helpers shipped with 0.2 accept both versions; 0.1 helpers reject version 2.

New top-level fields are `timed_out`, `scope`, and `configuration`. `summary` adds `open|filtered`. Results now carry their actual transport, `response_bytes`, structured `http`, and expanded `tls` fields (`verification_attempted`, `verification_error`, `sha256`, `sans`). `tls.verified` can now be true after successful verification. Schema 2 deliberately prevents older consumers from assuming this field is always false.

HTTP evidence may now contain up to 16 KiB instead of a single 2048-byte read. A complete response is truncated at its header terminator. Headers preserve duplicates and normalize names. `response_bytes` counts captured socket/TLS bytes before any trimming or text substitution, not total wire bytes.

Schema-2 complete inventories include a Cartesian scope manifest: resolved addresses × scan ports × selected transport. Helpers check that result keys fully cover it. Partial and `--open` reports cannot be consumed as complete inventories.

## Policies and diffs

Policy schema remains 1 and old fields retain their meanings. `allow_ports` always means TCP. UDP permissions use `allow_udp_ports`. Stronger optional fields are documented in USAGE.md. The updated example policy intentionally requires verification and exact coverage; an old report lacking these observations may fail it.

Diff output retains its schema version. It now includes certificate fingerprints, SANs, verification state, and selected HTTP observations. Comparisons across versions or differing probe settings can produce expected metadata changes. Use equal endpoint scope and equivalent probe settings for drift monitoring; `--require-same-scope` enforces only endpoint equality.

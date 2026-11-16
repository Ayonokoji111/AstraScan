# Roadmap

These are proposed directions, not implemented features or delivery commitments.

## Inventory quality

- Opt-in certificate chain/hostname verification and SAN reporting.
- A separately maintained, licensed service fingerprint format with evidence confidence.
- HTTP parsing that handles split headers and extracts structured fields within hard size/deadline limits.
- More local fixtures for retry behavior, packet loss, unreachable networks, TLS failure modes, and descriptor exhaustion.

## Reliability and scale

- Streaming JSON Lines output and bounded-memory result sinks.
- Resumable inventories with explicit scope manifests and integrity checks.
- Cancellable DNS resolution and a whole-scan deadline.
- Adaptive concurrency using measured resource limits and network conditions.

## Platform and interface

- Tested macOS support and eventually a Windows socket backend.
- Versioned C++ library API and reusable reporting library.
- A local report viewer with filtering, without changing report privacy defaults.

UDP, raw SYN scanning, OS fingerprinting, and a protocol scripting engine would require substantial independent design and validation. They are not in this initial implementation.

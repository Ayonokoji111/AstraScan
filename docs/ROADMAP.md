# Roadmap

Proposed directions; none are delivery commitments.

## Accuracy and protocol coverage

- Protocol-specific UDP queries and response correlation, with local fixtures and explicit payload side effects.
- A licensed service signature format and a confidence model broader than the current port hints and three banner prefixes.
- STARTTLS upgrades and richer certificate-chain reporting.
- HTTP informational responses, redirect observations, and optional structured response-field checks.
- Opt-in revocation handling with explicit network/privacy behavior.

## Reliability and scale

- Streaming JSON Lines and bounded-memory result sinks.
- Resumable inventories with signed scope/probe manifests.
- Cancellable DNS resolution and stronger process-level deadline controls.
- Resource-aware concurrency and controlled network-namespace fixtures for loss/ICMP behavior.
- Benchmarks against clearly specified workloads before making speed/accuracy comparisons.

## Platform and interface

- Validated macOS support and a Windows socket backend.
- A versioned C++ library API and local report viewer.
- More comprehensive inventory history and policy value validation.

Raw SYN scanning, OS fingerprinting, discovery, and a scripting engine require substantial separate work. AstraScan 0.2 implements generic UDP observations, TLS verification, and stronger inventory policies; it does not claim Nmap feature parity.

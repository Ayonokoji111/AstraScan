# Security

AstraScan 0.1.x is an early release. Use it only on systems you own or have permission to assess. TCP connections, TLS handshakes, and HTTP HEAD requests can be logged and can affect fragile services. Start with a scope preview and conservative rate/concurrency.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** option if private reporting is available. Otherwise contact the maintainer through the contact information on their GitHub profile before sharing sensitive details. Public issues are appropriate for non-sensitive correctness bugs. Do not post credentials, private scan inventories, or exploit details for unrelated live systems.

A useful report includes the affected version, input, observed result, expected security property, and a local reproduction with synthetic data. There is no guaranteed response SLA or independent security certification.

## Security boundaries

Remote banners and certificate metadata are untrusted. HTML escapes them; CSV neutralizes formula prefixes; terminal evidence strips controls. Socket and evidence buffers are bounded. Report files use restrictive permissions and atomic replacement. Inventory paths supplied by the local user are trusted input: existing output files are overwritten when requested.

TLS inspection does not validate certificate chains or hostnames. A negotiated TLS session is not proof of a trusted endpoint. The policy checker tests handshake/expiration observations, not TLS trust or cryptographic strength. Port-based service names are guesses unless a recognized response prefix is present.

Reports may contain internal IP addresses, hostnames, service versions, and certificates. Keep them private unless intentionally shared. No telemetry is sent. The scanner contacts resolved targets directly and uses your system DNS resolver. The report helpers operate on local files only.

## Repository review guidance

Changes should preserve strict scope limits, explicit protocol probes, cancellation, bounded reads, output-context escaping, and complete-report checks. High-risk changes include arbitrary scripts, subprocess plugins, raw packets, report template injection, unbounded CIDR expansion, and changes to trust or service-confidence semantics. Review these independently before merging.

# Security

AstraScan 0.2.x is an early release. Assess only systems you own or are authorized to inspect. TCP connections, UDP datagrams, TLS handshakes, and HTTP requests may be logged or affect fragile services. Preview scope and choose suitable rate/concurrency.

## Reporting

Use GitHub **Security → Report a vulnerability** if private reporting is enabled. Otherwise use the maintainer's GitHub profile contact details before sharing sensitive information. Public issues are appropriate for non-sensitive correctness bugs. Include version, synthetic input, expected property, observed behavior, and a local reproduction. Do not publish private inventories, credentials, or unrelated live-system exploit details. No response SLA or security certification is promised.

## Boundaries

Remote evidence is untrusted. HTML uses escaping and a restrictive CSP; CSV neutralizes formula prefixes; text strips controls. Evidence/probe buffers, scope, and worker count are bounded. Existing user-selected report paths are intentionally replaced with private files through atomic rename. Reports can include hostnames, service metadata, TLS certificates, and sensitive HTTP headers/cookies; keep them private unless deliberately shared. Report files are ignored by Git.

UDP silence is inconclusive. Closed/refused observations can originate from intermediaries. A port service label is a guess unless recognized from response evidence. Header-presence policies do not validate header semantics or establish application safety.

TLS trust checks are opt-in. `--verify-tls` checks chain, server purpose/time, and target DNS/IP identity against system roots. `--ca-file` uses the selected PEM bundle instead. `--server-name` deliberately overrides identity for every target in that invocation. Observation still proceeds when trust fails; enforce `require_verified_tls_ports` in policy when needed. Verification does not include OCSP, online revocation, certificate transparency, or downloaded intermediates. It reflects the local trust configuration and scan time.

Policies reject incomplete/filtered inventories and can require explicit endpoint coverage. They cannot authenticate a report or prove unscanned systems are compliant. Scanner exit 0 does not imply policy compliance or trusted TLS. Scope equality does not guarantee equivalent probe configuration.

No telemetry is sent. Scans contact resolved target addresses directly; the system resolver handles DNS. Python report helpers make no outbound connections.

## Review guidance

Preserve explicit scope, transport identity, response ambiguity, timeouts, bounds, cancellation, certificate observation/verification separation, and output escaping. Review arbitrary plugin execution, raw packet support, unbounded scope/evidence, report templates, and changes to policy confidence semantics independently before merging.

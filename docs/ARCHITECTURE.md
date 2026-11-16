# Architecture

AstraScan has a C++20 scanning core and two local Python inventory consumers. It never shells out to Nmap or uses privileged packet APIs.

```text
CLI / target files
        |
  validation + CIDR expansion + DNS + exclusions + deduplication
        |
  scope manifest: resolved hosts × sorted ports × selected transport
        |
  atomic task index → bounded workers → serialized attempt-start limiter
        |                        |
        |                 nonblocking TCP / UDP socket
        |                        |
        |          TCP: banner / TLS / HTTP  |  UDP: datagram + response
        |                        |
        +--------------- finalized result
                                 |
                         deterministic sorting
                                 |
                       text / JSON / CSV / HTML
                                 |
                      local JSON inventory consumers
                       /                       \
                   astra-diff               astra-policy
```

## Source map

| File | Responsibility |
| --- | --- |
| `include/astra/astra.hpp` | Configuration, observations, report model, public functions |
| `src/config.cpp` | Argument/port/hex parsing, files, CIDR, resolver, exclusions |
| `src/scanner.cpp` | Socket RAII, deadline polling, workers, rate limiter, probes, TLS verification |
| `src/http.cpp` | Bounded evidence parsing into status and duplicate-preserving headers |
| `src/report.cpp` | Versioned JSON and context-specific text/HTML/CSV serializers |
| `src/main.cpp` | Signals, orchestration, exit status, atomic private report writes |
| `tools/astra-diff.py` | Complete report and scope validation, stable observation comparison |
| `tools/astra-policy.py` | Exposure, trust, HTTP presence, and mandatory coverage requirements |

## Runtime contracts

1. Scope resolves before scan sockets are created. DNS/system filesystem calls are outside preemptible socket waits. CIDR and task caps fail before scanning.
2. One worker owns at most one active socket. RAII closes every attempt. Worker count is bounded at 512 and task count; the OS's descriptor limits still apply.
3. The global limiter serializes slot reservation against actual monotonic time and rechecks cancellation/deadline while waiting. Each retry counts as an attempt. It does not rate-limit every packet.
4. Phase deadlines and the overall deadline use `steady_clock`. Socket polls check cancellation at most every 50 ms; limiter sleeps check every 20 ms. Worker exceptions are captured, other workers stop, threads join, and the exception reaches the main error handler.
5. The signal handler sets a statically verified lock-free atomic flag. No serialization or thread join occurs in the handler. Signal and deadline outcomes are reported separately.
6. TCP openness depends on connection success, not later probe success. UDP openness requires a received datagram, including zero-length replies. A UDP timeout stays `open|filtered`. Refused attempts are not retried.
7. Passive and UDP evidence is capped at 2048 bytes. HTTP assembly is capped at 16384 captured bytes and 100 parsed fields. SAN output is capped at 128 entries and 253 bytes per DNS name. Remote controls/non-ASCII become dots; collection is not binary-forensic capture.
8. Each TLS worker owns an independent SSL session, X509 verification context, and certificate references. A read-only SSL context/trust store is shared. Observation handshakes remain independent from post-handshake chain, purpose, time, and identity checks. No intermediates or revocation data are downloaded.
9. Reports retain finalized observations in memory and sort them deterministically. Scope/configuration and partial/filtered flags let consumers identify what was actually scanned. Complete schema-2 reports must cover the declared Cartesian scope exactly.
10. Output escaping is context-specific. Report writes use `mkstemp`, restrictive permissions, file fsync, and same-directory rename. Inventory paths are trusted local inputs; an existing destination is intentionally replaced.
11. Policy requirements are evaluated only against observations and optional explicit required coverage. Closed endpoints do not satisfy an availability claim. Header presence is not a semantic security audit. Neither helper establishes report authenticity.

## Complexity and limits

Scope expansion is limited to 65,536 addresses (default 4096), and planned work to 1,000,000 endpoints. Results and bounded evidence remain in memory until rendering; memory grows with task count and evidence volume. This is not a streaming Internet-scale engine. Renderer output is also buffered before atomic writing.

System DNS, CA loading, certificate verification CPU work, and filesystem behavior depend on the host. The overall scan deadline controls scheduling and socket waits rather than forcibly killing these calls. TLS inherits OpenSSL's protocol security defaults. There is no process/plugin execution, packet crafting, raw ICMP parser, NSE equivalent, or vulnerability database.

## Extension requirements

New probes need explicit opt-in/port selection, bounded I/O/deadlines, evidence-source labels, side-effect documentation, and local fixtures. Incompatible report changes need a schema version and migration notes. Streaming output, cancellable resolution, broader signatures, STARTTLS, and cross-platform support need independent design and validation; see the roadmap.

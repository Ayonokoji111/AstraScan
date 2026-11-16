# Architecture

AstraScan has a small C++20 scanning core and two standalone Python inventory consumers. It never shells out to Nmap or invokes privileged packet APIs.

```text
CLI / target files
        |
  validation + CIDR expansion + DNS + exclusion + deduplication
        |
  hosts × sorted ports (bounded task count)
        |
  atomic task index → bounded worker pool → global start-rate limiter
        |                                   |
        |                            nonblocking TCP connect
        |                                   |
        |                       optional banner / TLS / HTTP probe
        |                                   |
        +---------------- finalized result --+
                            |
                   deterministic sorting
                            |
                  text / JSON / CSV / HTML
                            |
                    JSON inventory consumers
                    /                      \
                astra-diff              astra-policy
```

## Source map

| File | Responsibility |
| --- | --- |
| `include/astra/astra.hpp` | Shared configuration, result model, API |
| `src/config.cpp` | Strict integer/port parsing, target files, CIDR, resolver, exclusions |
| `src/scanner.cpp` | Socket RAII, deadline polling, worker pool, rate limiter, probes |
| `src/report.cpp` | Serialization and context-specific output escaping |
| `src/main.cpp` | Signals, CLI orchestration, exit codes, atomic report writing |
| `tools/astra-diff.py` | Complete-report validation and stable inventory comparison |
| `tools/astra-policy.py` | CIDR policy matching and exposure/certificate rules |

## Runtime contracts

1. The full scope resolves before any TCP scan starts. Every unique resolved address is scanned once. Invalid input or excess scope fails before scanning.
2. A worker owns one socket at a time. RAII closes it on each attempt. Total workers cannot exceed 512 or task count. The process still depends on available file descriptors and memory.
3. Every connect attempt reserves one globally spaced start slot. Sleeping workers check cancellation every 20 ms. Socket poll loops use an absolute phase deadline and check cancellation at most every 50 ms.
4. A refused connection is not retried. Timeouts and other connect errors are retried up to the configured bound. Application/TLS probe failures are not retried and do not change an open TCP state.
5. The signal handler only sets a statically verified lock-free `atomic<bool>` flag. Workers stop, threads join, and finalized results are serialized in the main thread. DNS and filesystem operations are not forcibly interrupted by this mechanism.
6. Results use a mutex only when appending. Work distribution uses an atomic index. TLS workers use independent SSL sessions with a shared read-only context.
7. Reports include only finalized tasks. `planned`, `completed`, `cancelled`, and `only_open` prevent consumers from mistaking partial/filtered reports for complete inventories.
8. Banner buffers are bounded to 2048 bytes; certificate names are bounded to 2047 bytes. Remote controls/binary bytes become dots; JSON strings escape non-ASCII bytes. This is an ASCII-oriented representation, not Unicode-preserving forensic capture.
9. Writers escape for the actual destination: JSON quoting, HTML entities, CSV quoting/formula neutralization, and control-free text. HTML contains no scripts.
10. Inventory helpers treat stored data as observations. They do not make outbound connections. A caller can forge a report; neither tool establishes its authenticity.

## Scope and complexity

The total number of planned tasks is capped at 1,000,000. Scope expansion is capped at 65,536 addresses (default 4,096). All finalized results are retained in memory until the scan completes; memory use grows linearly with task count and collected evidence. This is intentionally a bounded inventory utility, not an Internet-scale scan engine. An IPv4 CIDR is validated against the host cap before expansion.

Resolver, filesystem, and TLS library behavior depend on the host environment. TLS uses OpenSSL 3 and does not override its system security defaults. There is no packet crafting, process execution, payload plugin API, arbitrary script loading, vulnerability database, or remote execution capability.

## Extension points

Add a new protocol only with explicit port selection, bounded I/O/deadlines, evidence-source labeling, local fixtures, and documentation of side effects. Introduce incompatible report changes under a new schema version. Streaming reports, system resolver cancellation, full certificate validation, and Windows support require separate architectural work; see the roadmap.

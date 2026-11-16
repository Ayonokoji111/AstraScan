# Contributing

Use Linux, a C++20 compiler, GNU Make, OpenSSL 3 development headers, Python 3.9+, and the `openssl` executable for TLS fixtures. A no-TLS build needs no OpenSSL library but still uses Python for tests.

```bash
make -j2
make test
make TLS=0 BUILD=build-no-tls test

# Optional CMake / sanitizers
cmake -S . -B build-sanitize -DASTRA_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize -j2
ctest --test-dir build-sanitize --output-on-failure
```

Tests contact only loopback addresses. They verify port parsing, scope limits, deduplication, exclusions, open/refused connections, passive SSH, HTTP HEAD, HTML/CSV escaping, IPv6 (skipped if unavailable), rate limits, output files, signals, TLS with a generated local certificate, diff behavior, and policy behavior. TLS fixtures require 8443 to be available; HTTP fixtures try 8080, 8000, then 8888. Do not run multiple integration suites simultaneously on the same machine.

Use a separate build directory for different compilers or TLS/sanitizer flags. `make` does not track command-line flag changes. Integration test servers never bind outside loopback.

Before opening a pull request:

- Explain the user-visible trigger and behavior change.
- Keep timeouts, memory bounds, probe side effects, and service-confidence reporting explicit.
- Add focused local tests for changed behavior, without scanning third-party targets.
- Update CLI docs and schema when changing report fields or semantics.
- Do not submit captured private inventories, tokens, certificates/private keys, or credentials.

The project uses MIT licensing. Contributions must be original or compatibly licensed. No Nmap source, databases, or scripts should be copied into this project. Report vulnerabilities through the guidance in SECURITY.md.

#pragma once
#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <vector>

namespace astra {
inline constexpr const char *version = "0.1.0";
static_assert(std::atomic<bool>::is_always_lock_free, "Cancellation must be signal-safe");
extern std::atomic<bool> interrupted;
struct Config {
    std::vector<std::string> targets, excludes;
    std::vector<uint16_t> ports;
    unsigned workers = 64, timeout_ms = 700, retries = 0, rate = 200, max_hosts = 4096;
    bool services = false, tls = false, http = false, only_open = false, dry_run = false;
    std::string format = "text", output;
};
struct Host {
    std::string input, address;
    int family = 0;
};
struct Result {
    std::string target, address, state, service, evidence, tls_subject, tls_issuer, tls_expiry;
    uint16_t port = 0;
    double latency_ms = 0;
    unsigned attempts = 0;
    bool tls_handshake = false;
    std::string tls_protocol, tls_cipher, error;
};
struct Report {
    std::string started_at;
    double elapsed_ms = 0;
    size_t planned = 0;
    bool cancelled = false;
    std::vector<Result> results;
};
unsigned number(const std::string &, unsigned low, unsigned high, const std::string &label);
std::vector<uint16_t> parse_ports(const std::string &);
Config parse_args(int argc, char **argv);
std::vector<Host> resolve_targets(const Config &);
Report scan(const Config &, const std::vector<Host> &);
std::string render(const Config &, const Report &);
std::string json_escape(const std::string &);
std::string html_escape(const std::string &);
std::string help();
} // namespace astra

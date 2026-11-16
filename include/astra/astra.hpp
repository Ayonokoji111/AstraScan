#pragma once
#include <atomic>
#include <csignal>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace astra {
inline constexpr const char *version = "0.2.0";
static_assert(std::atomic<bool>::is_always_lock_free, "Cancellation must be signal-safe");
extern std::atomic<bool> interrupted;
struct Config {
    std::vector<std::string> targets, excludes;
    std::vector<uint16_t> ports;
    std::vector<uint16_t> tls_ports = {443, 8443, 465, 636, 993, 995};
    std::vector<uint16_t> http_ports = {80, 8000, 8080, 8888, 9200, 443, 8443};
    std::string transport = "tcp", ca_file, server_name;
    std::vector<unsigned char> udp_payload;
    unsigned deadline_ms = 0;
    bool verify_tls = false;
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
    std::string transport = "tcp", service_source = "port_hint";
    size_t response_bytes = 0;
    bool tls_verification_attempted = false, tls_verified = false;
    std::string tls_verification_error, tls_sha256;
    std::vector<std::string> tls_sans;
    int http_status = 0;
    bool http_headers_complete = false;
    std::vector<std::pair<std::string, std::string>> http_headers;
    bool tls_handshake = false;
    std::string tls_protocol, tls_cipher, error;
};
struct Report {
    std::string started_at;
    double elapsed_ms = 0;
    size_t planned = 0;
    bool cancelled = false, timed_out = false;
    std::vector<Host> hosts;
    std::vector<Result> results;
};
unsigned number(const std::string &, unsigned low, unsigned high, const std::string &label);
std::vector<uint16_t> parse_ports(const std::string &);
Config parse_args(int argc, char **argv);
std::vector<Host> resolve_targets(const Config &);
Report scan(const Config &, const std::vector<Host> &);
void parse_http(Result &);
std::string render(const Config &, const Report &);
std::string json_escape(const std::string &);
std::string html_escape(const std::string &);
std::string help();
} // namespace astra

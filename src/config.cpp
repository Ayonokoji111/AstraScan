#include "astra/astra.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <fstream>
#include <memory>
#include <netdb.h>
#include <set>
#include <sstream>
#include <stdexcept>
namespace astra {
unsigned number(const std::string &s, unsigned lo, unsigned hi, const std::string &label) {
    unsigned v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size() || v < lo || v > hi)
        throw std::runtime_error(label + " must be an integer in " + std::to_string(lo) + ".." +
                                 std::to_string(hi));
    return v;
}
std::vector<uint16_t> parse_ports(const std::string &s) {
    std::set<uint16_t> out;
    std::istringstream in(s);
    std::string token;
    if (s.empty() || s.back() == ',')
        throw std::runtime_error("empty port expression");
    while (std::getline(in, token, ',')) {
        auto dash = token.find('-');
        unsigned a = number(token.substr(0, dash), 1, 65535, "port"), b = a;
        if (dash != std::string::npos)
            b = number(token.substr(dash + 1), 1, 65535, "port");
        if (b < a)
            throw std::runtime_error("descending port range");
        for (unsigned p = a; p <= b; ++p)
            out.insert(static_cast<uint16_t>(p));
    }
    return {out.begin(), out.end()};
}
static void read_list(const std::string &path, std::vector<std::string> &out) {
    std::ifstream f(path);
    if (!f)
        throw std::runtime_error("cannot read target file: " + path);
    std::string line;
    while (std::getline(f, line)) {
        line = line.substr(0, line.find('#'));
        std::istringstream words(line);
        std::string w;
        while (words >> w)
            out.push_back(w);
    }
    if (f.bad())
        throw std::runtime_error("failed reading target file: " + path);
}
Config parse_args(int argc, char **argv) {
    Config c;
    c.ports = parse_ports("21,22,25,53,80,110,135,139,143,443,445,587,993,995,1433,1521,3306,3389,"
                          "5432,5900,6379,8000,8080,8443,9200,27017");
    bool ports_set = false, udp_payload_set = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto value = [&]() {
            if (++i >= argc)
                throw std::runtime_error("missing value for " + a);
            return std::string(argv[i]);
        };
        if (a == "--ports" || a == "-p") {
            c.ports = parse_ports(value());
            ports_set = true;
        } else if (a == "--target-file" || a == "-iL")
            read_list(value(), c.targets);
        else if (a == "--exclude")
            c.excludes.push_back(value());
        else if (a == "--exclude-file")
            read_list(value(), c.excludes);
        else if (a == "--workers")
            c.workers = number(value(), 1, 512, a);
        else if (a == "--timeout")
            c.timeout_ms = number(value(), 10, 60000, a);
        else if (a == "--retries")
            c.retries = number(value(), 0, 5, a);
        else if (a == "--rate")
            c.rate = number(value(), 1, 100000, a);
        else if (a == "--deadline")
            c.deadline_ms = number(value(), 1, 86400000, a);
        else if (a == "--udp")
            c.transport = "udp";
        else if (a == "--udp-payload-hex") {
            auto hex = value();
            udp_payload_set = true;
            c.udp_payload.clear();
            if (hex.size() % 2 || hex.size() > 1024)
                throw std::runtime_error(
                    "UDP hex payload must have an even length, at most 512 bytes");
            auto digit = [](char ch) -> unsigned {
                if (ch >= '0' && ch <= '9')
                    return static_cast<unsigned>(ch - '0');
                if (ch >= 'a' && ch <= 'f')
                    return static_cast<unsigned>(ch - 'a' + 10);
                if (ch >= 'A' && ch <= 'F')
                    return static_cast<unsigned>(ch - 'A' + 10);
                throw std::runtime_error("invalid UDP hex payload");
            };
            for (size_t j = 0; j < hex.size(); j += 2)
                c.udp_payload.push_back(
                    static_cast<unsigned char>((digit(hex[j]) << 4) | digit(hex[j + 1])));
        } else if (a == "--tls-ports") {
            c.tls_ports = parse_ports(value());
            c.tls = true;
        } else if (a == "--http-ports") {
            c.http_ports = parse_ports(value());
            c.http = true;
        } else if (a == "--verify-tls") {
            c.verify_tls = true;
            c.tls = true;
        } else if (a == "--ca-file") {
            c.ca_file = value();
            c.verify_tls = true;
            c.tls = true;
        } else if (a == "--server-name")
            c.server_name = value();
        else if (a == "--max-hosts")
            c.max_hosts = number(value(), 1, 65536, a);
        else if (a == "--format")
            c.format = value();
        else if (a == "--output" || a == "-o")
            c.output = value();
        else if (a == "--services")
            c.services = true;
        else if (a == "--tls")
            c.tls = true;
        else if (a == "--http")
            c.http = true;
        else if (a == "--open")
            c.only_open = true;
        else if (a == "--dry-run")
            c.dry_run = true;
        else if (a == "--all-ports") {
            c.ports = parse_ports("1-65535");
            ports_set = true;
        } else if (a == "--") {
            while (++i < argc)
                c.targets.push_back(argv[i]);
            break;
        } else if (!a.empty() && a[0] == '-')
            throw std::runtime_error("unknown option: " + a);
        else
            c.targets.push_back(a);
    }
    if (c.transport == "udp") {
        if (!ports_set)
            c.ports = parse_ports("53,123,161,500,1900,4500,5353");
        if (c.services || c.tls || c.http || !c.server_name.empty())
            throw std::runtime_error("UDP scans cannot use TCP service, HTTP or TLS options");
    } else if (udp_payload_set)
        throw std::runtime_error("--udp-payload-hex requires --udp");
    if (!c.server_name.empty()) {
        if (c.server_name.size() > 253 ||
            c.server_name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") !=
                std::string::npos)
            throw std::runtime_error(
                "--server-name must be a DNS name or IP literal without URL syntax");
        if (!c.tls && !c.http)
            throw std::runtime_error("--server-name requires HTTP or TLS inspection");
    }
    if (c.targets.empty())
        throw std::runtime_error("at least one target is required (try --help)");
    if (c.format != "text" && c.format != "json" && c.format != "csv" && c.format != "html")
        throw std::runtime_error("format must be text, json, csv or html");
#ifndef ASTRA_TLS
    if (c.tls)
        throw std::runtime_error("this build has no TLS support; rebuild with OpenSSL");
#endif
    return c;
}
static std::vector<std::string> expand(const std::string &s, unsigned cap) {
    auto slash = s.find('/');
    if (slash == std::string::npos)
        return {s};
    in_addr ip{};
    if (inet_pton(AF_INET, s.substr(0, slash).c_str(), &ip) != 1)
        throw std::runtime_error("CIDR requires an IPv4 address: " + s);
    unsigned bits = number(s.substr(slash + 1), 0, 32, "CIDR prefix");
    uint64_t count = uint64_t{1} << (32 - bits);
    if (count > cap)
        throw std::runtime_error("CIDR exceeds --max-hosts: " + s);
    uint32_t base = ntohl(ip.s_addr) & (bits == 0 ? 0u : (0xffffffffu << (32 - bits)));
    std::vector<std::string> out;
    for (uint64_t i = 0; i < count; ++i) {
        in_addr a{htonl(base + static_cast<uint32_t>(i))};
        char b[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, b, sizeof b);
        out.emplace_back(b);
    }
    return out;
}
static std::vector<Host> resolve(const std::string &s) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *raw = nullptr;
    int e = getaddrinfo(s.c_str(), nullptr, &hints, &raw);
    if (e)
        throw std::runtime_error("cannot resolve " + s + ": " + gai_strerror(e));
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> list(raw, freeaddrinfo);
    std::vector<Host> out;
    for (auto *p = raw; p; p = p->ai_next) {
        char b[NI_MAXHOST];
        if (getnameinfo(p->ai_addr, p->ai_addrlen, b, sizeof b, nullptr, 0, NI_NUMERICHOST) == 0)
            out.push_back({s, b, p->ai_family});
    }
    if (out.empty())
        throw std::runtime_error("no IP addresses for " + s);
    return out;
}
std::vector<Host> resolve_targets(const Config &c) {
    std::set<std::string> excluded, seen;
    for (const auto &x : c.excludes)
        for (const auto &s : expand(x, c.max_hosts))
            for (const auto &h : resolve(s))
                excluded.insert(h.address);
    std::vector<Host> out;
    for (const auto &x : c.targets)
        for (const auto &s : expand(x, c.max_hosts))
            for (auto h : resolve(s)) {
                if (excluded.count(h.address) || !seen.insert(h.address).second)
                    continue;
                if (out.size() >= c.max_hosts)
                    throw std::runtime_error("resolved target count exceeds --max-hosts");
                h.input = x.find('/') == std::string::npos ? x : s;
                out.push_back(std::move(h));
            }
    if (out.empty())
        throw std::runtime_error("no targets remain after exclusions");
    if (out.size() * c.ports.size() > 1000000)
        throw std::runtime_error("scan exceeds 1,000,000 host/port tasks; split the scope");
    return out;
}
std::string help() {
    return R"(AstraScan 0.2.0 — concurrent TCP/UDP inventory and service inspection
Usage: astrascan [options] TARGET [TARGET...]
Targets: hostname, IPv4, IPv6, or IPv4 CIDR (all CIDR addresses included)
  -p, --ports LIST       Ports/ranges, e.g. 22,80,443,8000-8010
      --udp              UDP mode (default: TCP); timeouts are open|filtered
      --udp-payload-hex H Optional UDP payload, max 512 bytes; default empty
      --deadline MS      Scan deadline after DNS; emits partial report (exit 124)
      --tls-ports LIST   TLS probe ports; enables TLS, does not set scan ports
      --http-ports LIST  HTTP probe ports; enables HTTP, does not set scan ports
      --verify-tls       Verify TLS chain and target identity after handshake
      --ca-file FILE     Use a PEM trust bundle; enables verification
      --server-name NAME Override TLS/HTTP identity for every target (no DNS change)
      --all-ports        Scan selected transport ports 1-65535
  -iL, --target-file F   Whitespace-separated targets; # comments supported
      --exclude TARGET  Exclude address, hostname, or IPv4 CIDR (repeatable)
      --exclude-file F  Read exclusions from file
      --max-hosts N     Expansion cap, default 4096; maximum 65536
      --workers N       Concurrent tasks, default 64; maximum 512
      --rate N          Global maximum connection starts/second, default 200
      --timeout MS      Timeout per connection/probe phase, default 700
      --retries N       Retry timeouts/network errors, default 0; maximum 5
      --services        Read a bounded passive banner on open ports
      --http            Send HTTP HEAD on common HTTP ports
      --tls             Inspect TLS on common TLS ports (OpenSSL build)
      --open            Only show open ports (summary still counts all)
      --dry-run         Resolve scope and show plan, without connecting
      --format FORMAT   text (default), json, csv, html
  -o, --output FILE     Write report to file, otherwise stdout
      --version         Show version/build capabilities
  -h, --help            Show help
SIGINT/SIGTERM stops new work and produces a partial report (exit 130).
Use only on systems you own or are authorized to assess.
)";
}
} // namespace astra

#include "astra/astra.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <exception>
#include <fcntl.h>
#include <iomanip>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#ifdef ASTRA_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif
namespace astra {
std::atomic<bool> interrupted{false};
using Clock = std::chrono::steady_clock;
struct RunState {
    Clock::time_point deadline = Clock::time_point::max();
    std::atomic<bool> failed{false};
    bool stopped() const {
        return interrupted || failed || Clock::now() >= deadline;
    }
    Clock::time_point phase(unsigned ms) const {
        return std::min(deadline, Clock::now() + std::chrono::milliseconds(ms));
    }
};
struct Socket {
    int fd;
    explicit Socket(int f) : fd(f) {}
    ~Socket() {
        if (fd >= 0)
            close(fd);
    }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
};
static bool ready(int fd, short events, Clock::time_point deadline, const RunState &run) {
    while (!run.stopped()) {
        const auto now = Clock::now();
        if (now >= deadline)
            return false;
        // poll() uses integer milliseconds. Rounding down would end a phase early,
        // allowing an overall deadline to be mistaken for successful completion.
        const auto ms = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        pollfd p{fd, events, 0};
        int n = poll(&p, 1, static_cast<int>(std::min<int64_t>(ms, 50)));
        if (n > 0)
            return true;
        if (n < 0 && errno != EINTR)
            return false;
    }
    return false;
}
static bool contains(const std::vector<uint16_t> &ports, uint16_t port) {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}
static std::string service(uint16_t p, const std::string &transport) {
    if (transport == "udp") {
        switch (p) {
        case 53:
            return "domain";
        case 123:
            return "ntp";
        case 161:
            return "snmp";
        case 500:
            return "isakmp";
        case 1900:
            return "ssdp";
        case 4500:
            return "ipsec-nat-t";
        case 5353:
            return "mdns";
        default:
            return "unknown";
        }
    }
    switch (p) {
    case 21:
        return "ftp";
    case 22:
        return "ssh";
    case 25:
    case 587:
        return "smtp";
    case 53:
        return "domain";
    case 80:
    case 8000:
    case 8080:
    case 8888:
    case 9200:
        return "http";
    case 110:
        return "pop3";
    case 135:
        return "msrpc";
    case 139:
        return "netbios-ssn";
    case 143:
        return "imap";
    case 443:
    case 8443:
        return "https";
    case 445:
        return "smb";
    case 465:
        return "smtps";
    case 636:
        return "ldaps";
    case 993:
        return "imaps";
    case 995:
        return "pop3s";
    case 1433:
        return "mssql";
    case 1521:
        return "oracle";
    case 3306:
        return "mysql";
    case 3389:
        return "rdp";
    case 5432:
        return "postgresql";
    case 5900:
        return "vnc";
    case 6379:
        return "redis";
    case 27017:
        return "mongodb";
    default:
        return "unknown";
    }
}
static std::string clean(const char *data, size_t n) {
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        auto c = static_cast<unsigned char>(data[i]);
        out += ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') ? static_cast<char>(c)
                                                                              : '.';
    }
    return out;
}
static std::string identity(const Host &h, const Config &c) {
    auto name = c.server_name.empty() ? h.input : c.server_name;
    auto zone = name.find('%');
    if (zone != std::string::npos)
        name.resize(zone);
    return name;
}
static std::string request(const Host &h, const Config &c, uint16_t port) {
    std::string host = identity(h, c);
    if (host.find_first_of("\r\n\t /\\") != std::string::npos)
        host = h.address;
    if (host.find(':') != std::string::npos)
        host = "[" + host + "]";
    if (port != 80 && port != 443)
        host += ":" + std::to_string(port);
    return "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: AstraScan/" + version +
           "\r\nConnection: close\r\n\r\n";
}
static void finish_http(Result &r) {
    auto end = r.evidence.find("\r\n\r\n");
    if (end != std::string::npos)
        r.evidence.resize(end + 4);
    parse_http(r);
}
#ifdef ASTRA_TLS
static bool tls_wait(SSL *ssl, int rc, int fd, Clock::time_point deadline, const RunState &run) {
    int e = SSL_get_error(ssl, rc);
    return (e == SSL_ERROR_WANT_READ && ready(fd, POLLIN, deadline, run)) ||
           (e == SSL_ERROR_WANT_WRITE && ready(fd, POLLOUT, deadline, run));
}
static void certificate_metadata(X509 *cert, SSL *ssl, SSL_CTX *ctx, const Host &h, const Config &c,
                                 Result &r) {
    char b[2048]{};
    if (X509_NAME_oneline(X509_get_subject_name(cert), b, sizeof b))
        r.tls_subject = clean(b, std::strlen(b));
    if (X509_NAME_oneline(X509_get_issuer_name(cert), b, sizeof b))
        r.tls_issuer = clean(b, std::strlen(b));
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (bio) {
        ASN1_TIME_print(bio.get(), X509_get0_notAfter(cert));
        char *p = nullptr;
        long n = BIO_get_mem_data(bio.get(), &p);
        if (n > 0)
            r.tls_expiry = std::string(p, static_cast<size_t>(n));
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned size = 0;
    if (X509_digest(cert, EVP_sha256(), digest, &size)) {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned i = 0; i < size; ++i)
            hex << std::setw(2) << static_cast<unsigned>(digest[i]);
        r.tls_sha256 = hex.str();
    }
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
        static_cast<GENERAL_NAMES *>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)),
        GENERAL_NAMES_free);
    if (names)
        for (int i = 0; i < std::min(sk_GENERAL_NAME_num(names.get()), 128); ++i) {
            const auto *entry = sk_GENERAL_NAME_value(names.get(), i);
            if (entry->type == GEN_DNS) {
                const auto *name = entry->d.dNSName;
                int len = ASN1_STRING_length(name);
                if (len >= 0 && len <= 253)
                    r.tls_sans.push_back(
                        "DNS:" + clean(reinterpret_cast<const char *>(ASN1_STRING_get0_data(name)),
                                       static_cast<size_t>(len)));
            } else if (entry->type == GEN_IPADD) {
                const auto *ip = entry->d.iPAddress;
                int len = ASN1_STRING_length(ip);
                char text[INET6_ADDRSTRLEN];
                if ((len == 4 || len == 16) &&
                    inet_ntop(len == 4 ? AF_INET : AF_INET6, ASN1_STRING_get0_data(ip), text,
                              sizeof text))
                    r.tls_sans.push_back("IP:" + std::string(text));
            }
        }
    if (!c.verify_tls)
        return;
    r.tls_verification_attempted = true;
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> store(X509_STORE_CTX_new(),
                                                                          X509_STORE_CTX_free);
    if (!store || X509_STORE_CTX_init(store.get(), SSL_CTX_get_cert_store(ctx), cert,
                                      SSL_get_peer_cert_chain(ssl)) != 1) {
        r.tls_verification_error = "verification initialization failed";
        return;
    }
    auto *params = X509_STORE_CTX_get0_param(store.get());
    X509_VERIFY_PARAM_set_purpose(params, X509_PURPOSE_SSL_SERVER);
    auto name = identity(h, c);
    in_addr ip4{};
    in6_addr ip6{};
    bool ip =
        inet_pton(AF_INET, name.c_str(), &ip4) == 1 || inet_pton(AF_INET6, name.c_str(), &ip6) == 1;
    X509_VERIFY_PARAM_set_hostflags(params, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    int configured = ip ? X509_VERIFY_PARAM_set1_ip_asc(params, name.c_str())
                        : X509_VERIFY_PARAM_set1_host(params, name.c_str(), name.size());
    if (configured != 1) {
        r.tls_verification_error = "invalid verification identity";
        return;
    }
    r.tls_verified = X509_verify_cert(store.get()) == 1;
    if (!r.tls_verified)
        r.tls_verification_error =
            X509_verify_cert_error_string(X509_STORE_CTX_get_error(store.get()));
}
static void inspect_tls(int fd, const Host &h, const Config &c, Result &r, SSL_CTX *ctx,
                        const RunState &run) {
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx), SSL_free);
    if (!ssl) {
        r.error = "TLS allocation failed";
        return;
    }
    SSL_set_fd(ssl.get(), fd);
    auto name = identity(h, c);
    in_addr ip4{};
    in6_addr ip6{};
    if (inet_pton(AF_INET, name.c_str(), &ip4) != 1 && inet_pton(AF_INET6, name.c_str(), &ip6) != 1)
        SSL_set_tlsext_host_name(ssl.get(), name.c_str());
    auto deadline = run.phase(c.timeout_ms);
    int rc;
    while (!run.stopped()) {
        ERR_clear_error();
        rc = SSL_connect(ssl.get());
        if (rc == 1)
            break;
        if (!tls_wait(ssl.get(), rc, fd, deadline, run)) {
            r.error = "TLS handshake failed or timed out";
            return;
        }
    }
    if (run.stopped())
        return;
    r.tls_handshake = true;
    r.tls_protocol = SSL_get_version(ssl.get());
    r.tls_cipher = SSL_get_cipher_name(ssl.get());
    std::unique_ptr<X509, decltype(&X509_free)> cert(SSL_get1_peer_certificate(ssl.get()),
                                                     X509_free);
    if (cert)
        certificate_metadata(cert.get(), ssl.get(), ctx, h, c, r);
    else if (c.verify_tls) {
        r.tls_verification_attempted = true;
        r.tls_verification_error = "peer supplied no certificate";
    }
    if (c.http && contains(c.http_ports, r.port)) {
        auto req = request(h, c, r.port);
        size_t sent = 0;
        deadline = run.phase(c.timeout_ms);
        while (sent < req.size() && !run.stopped()) {
            ERR_clear_error();
            rc = SSL_write(ssl.get(), req.data() + sent, static_cast<int>(req.size() - sent));
            if (rc > 0)
                sent += static_cast<size_t>(rc);
            else if (!tls_wait(ssl.get(), rc, fd, deadline, run)) {
                r.error = "HTTPS request failed or timed out";
                return;
            }
        }
        char b[2048];
        deadline = run.phase(c.timeout_ms);
        while (r.evidence.size() < 16384 && !run.stopped()) {
            ERR_clear_error();
            rc = SSL_read(ssl.get(), b,
                          static_cast<int>(std::min<size_t>(sizeof b, 16384 - r.evidence.size())));
            if (rc > 0) {
                r.response_bytes += static_cast<size_t>(rc);
                r.evidence += clean(b, static_cast<size_t>(rc));
                if (r.evidence.find("\r\n\r\n") != std::string::npos)
                    break;
            } else if (!tls_wait(ssl.get(), rc, fd, deadline, run))
                break;
        }
        finish_http(r);
    }
}
#endif
struct RateLimiter {
    std::mutex mutex;
    Clock::time_point next = Clock::now();
    bool wait(unsigned rate, const RunState &run) {
        std::unique_lock lock(mutex);
        while (!run.stopped() && Clock::now() < next)
            std::this_thread::sleep_for(std::min(
                next - Clock::now(),
                std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(20))));
        if (run.stopped())
            return false;
        next = Clock::now() + std::chrono::nanoseconds(1000000000ull / rate);
        return true;
    }
};
static int connect_to(int fd, const Host &h, uint16_t port, unsigned timeout, const RunState &run) {
    sockaddr_storage storage{};
    socklen_t len = 0;
    if (h.family == AF_INET) {
        auto *a = reinterpret_cast<sockaddr_in *>(&storage);
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        if (inet_pton(AF_INET, h.address.c_str(), &a->sin_addr) != 1)
            return EINVAL;
        len = sizeof *a;
    } else {
        auto *a = reinterpret_cast<sockaddr_in6 *>(&storage);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        auto ip = h.address;
        auto percent = ip.find('%');
        if (percent != std::string::npos) {
            auto scope = ip.substr(percent + 1);
            a->sin6_scope_id = if_nametoindex(scope.c_str());
            if (!a->sin6_scope_id) {
                try {
                    a->sin6_scope_id = number(scope, 1, 0xffffffffu, "scope");
                } catch (...) {
                    return EINVAL;
                }
            }
            ip.resize(percent);
        }
        if (inet_pton(AF_INET6, ip.c_str(), &a->sin6_addr) != 1)
            return EINVAL;
        len = sizeof *a;
    }
    if (connect(fd, reinterpret_cast<sockaddr *>(&storage), len) == 0)
        return 0;
    if (errno != EINPROGRESS)
        return errno;
    if (!ready(fd, POLLOUT, run.phase(timeout), run))
        return run.stopped() ? EINTR : ETIMEDOUT;
    int error = 0;
    socklen_t size = sizeof error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0)
        return errno;
    return error;
}
static int inspect_udp(int fd, const Config &c, Result &r, const RunState &run) {
    const void *data = c.udp_payload.empty() ? static_cast<const void *>("") : c.udp_payload.data();
    ssize_t sent = send(fd, data, c.udp_payload.size(), 0);
    if (sent < 0)
        return errno;
    if (!ready(fd, POLLIN, run.phase(c.timeout_ms), run))
        return run.stopped() ? EINTR : ETIMEDOUT;
    char b[2048];
    ssize_t n = recv(fd, b, sizeof b, 0);
    if (n < 0)
        return errno;
    r.response_bytes = static_cast<size_t>(n);
    r.evidence = clean(b, static_cast<size_t>(n));
    return 0;
}
static void inspect_plain(int fd, const Host &h, const Config &c, Result &r, const RunState &run) {
    bool http = c.http && contains(c.http_ports, r.port);
    if (http) {
        auto req = request(h, c, r.port);
        size_t sent = 0;
        auto deadline = run.phase(c.timeout_ms);
        while (sent < req.size() && !run.stopped()) {
            ssize_t n = send(fd, req.data() + sent, req.size() - sent, 0);
            if (n > 0)
                sent += static_cast<size_t>(n);
            else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
                     ready(fd, POLLOUT, deadline, run))
                continue;
            else {
                r.error = "HTTP request failed or timed out";
                return;
            }
        }
    }
    auto deadline = run.phase(c.timeout_ms);
    size_t limit = http ? 16384 : 2048;
    while (r.evidence.size() < limit && !run.stopped() && ready(fd, POLLIN, deadline, run)) {
        char b[2048];
        ssize_t n = recv(fd, b, std::min(sizeof b, limit - r.evidence.size()), 0);
        if (n > 0) {
            r.response_bytes += static_cast<size_t>(n);
            r.evidence += clean(b, static_cast<size_t>(n));
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        else
            break;
        if (!http || r.evidence.find("\r\n\r\n") != std::string::npos)
            break;
    }
    if (r.evidence.rfind("SSH-", 0) == 0) {
        r.service = "ssh";
        r.service_source = "banner";
    } else if (r.evidence.rfind("RFB ", 0) == 0) {
        r.service = "vnc";
        r.service_source = "banner";
    }
    if (r.evidence.rfind("HTTP/", 0) == 0)
        finish_http(r);
}
Report scan(const Config &c, const std::vector<Host> &hosts) {
    Report report;
    report.hosts = hosts;
    report.planned = hosts.size() * c.ports.size();
    auto start = Clock::now();
    RunState run;
    if (c.deadline_ms)
        run.deadline = start + std::chrono::milliseconds(c.deadline_ms);
    auto now = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&now, &tm);
    std::ostringstream timestamp;
    timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    report.started_at = timestamp.str();
    std::atomic<size_t> index{0};
    std::mutex results_mutex;
    RateLimiter limiter;
    std::exception_ptr failure;
#ifdef ASTRA_TLS
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
        c.tls ? SSL_CTX_new(TLS_client_method()) : nullptr, SSL_CTX_free);
    if (c.tls && !ctx)
        throw std::runtime_error("could not initialize OpenSSL");
    if (c.verify_tls) {
        int ok = c.ca_file.empty()
                     ? SSL_CTX_set_default_verify_paths(ctx.get())
                     : SSL_CTX_load_verify_locations(ctx.get(), c.ca_file.c_str(), nullptr);
        if (ok != 1)
            throw std::runtime_error("could not load TLS trust store");
    }
#endif
    auto worker = [&]() {
        try {
            while (!run.stopped()) {
                size_t i = index.fetch_add(1);
                if (i >= report.planned)
                    break;
                const auto &h = hosts[i / c.ports.size()];
                Result r;
                r.target = h.input;
                r.address = h.address;
                r.port = c.ports[i % c.ports.size()];
                r.transport = c.transport;
                r.service = service(r.port, c.transport);
                for (unsigned attempt = 0; attempt <= c.retries && !run.stopped(); ++attempt) {
                    if (!limiter.wait(c.rate, run))
                        break;
                    ++r.attempts;
                    auto t = Clock::now();
                    Socket socket(
                        ::socket(h.family, c.transport == "udp" ? SOCK_DGRAM : SOCK_STREAM, 0));
                    int error = 0;
                    if (socket.fd < 0)
                        error = errno;
                    else {
                        int flags = fcntl(socket.fd, F_GETFL, 0);
                        if (flags < 0 || fcntl(socket.fd, F_SETFL, flags | O_NONBLOCK) < 0)
                            error = errno;
                        else
                            error = connect_to(socket.fd, h, r.port, c.timeout_ms, run);
                    }
                    if (error == 0 && c.transport == "udp")
                        error = inspect_udp(socket.fd, c, r, run);
                    r.latency_ms =
                        std::chrono::duration<double, std::milli>(Clock::now() - t).count();
                    if (run.stopped())
                        break;
                    if (error == 0) {
                        r.state = "open";
                        r.error.clear();
                        if (c.transport == "tcp") {
#ifdef ASTRA_TLS
                            if (c.tls && contains(c.tls_ports, r.port))
                                inspect_tls(socket.fd, h, c, r, ctx.get(), run);
                            else
#endif
                                if (!contains(c.tls_ports, r.port) &&
                                    ((c.http && contains(c.http_ports, r.port)) || c.services))
                                inspect_plain(socket.fd, h, c, r, run);
                        }
                        break;
                    }
                    r.error = std::strerror(error);
                    r.state = error == ECONNREFUSED ? "closed"
                              : error == ETIMEDOUT
                                  ? (c.transport == "udp" ? "open|filtered" : "filtered")
                                  : "error";
                    if (r.state == "closed")
                        break;
                }
                if (!r.state.empty() && !run.stopped()) {
                    std::lock_guard lock(results_mutex);
                    report.results.push_back(std::move(r));
                }
            }
        } catch (...) {
            std::lock_guard lock(results_mutex);
            if (!failure)
                failure = std::current_exception();
            run.failed = true;
        }
    };
    std::vector<std::thread> threads;
    try {
        for (size_t i = 0; i < std::min<size_t>(c.workers, report.planned); ++i)
            threads.emplace_back(worker);
    } catch (...) {
        run.failed = true;
        for (auto &t : threads)
            t.join();
        throw;
    }
    for (auto &t : threads)
        t.join();
    if (failure)
        std::rethrow_exception(failure);
    std::sort(report.results.begin(), report.results.end(), [](const auto &a, const auto &b) {
        return a.address == b.address ? a.port < b.port : a.address < b.address;
    });
    report.cancelled = interrupted;
    report.timed_out =
        !interrupted && Clock::now() >= run.deadline && report.results.size() < report.planned;
    report.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    return report;
}
} // namespace astra

#include "astra/astra.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#ifdef ASTRA_TLS
#include <openssl/ssl.h>
#include <openssl/x509.h>
#endif
namespace astra {
std::atomic<bool> interrupted{false};
using Clock = std::chrono::steady_clock;
struct Socket {
    int fd = -1;
    explicit Socket(int f) : fd(f) {}
    ~Socket() {
        if (fd >= 0)
            close(fd);
    }
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
};
static bool ready(int fd, short events, Clock::time_point deadline) {
    while (!interrupted) {
        auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        if (ms <= 0)
            return false;
        pollfd p{fd, events, 0};
        int n = poll(&p, 1, static_cast<int>(std::min<int64_t>(ms, 50)));
        if (n > 0)
            return true;
        if (n < 0 && errno != EINTR)
            return false;
    }
    return false;
}
static std::string service(uint16_t p) {
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
    case 9200:
        return "http";
    case 27017:
        return "mongodb";
    default:
        return "unknown";
    }
}
static bool tls_port(uint16_t p) {
    return p == 443 || p == 8443 || p == 465 || p == 636 || p == 993 || p == 995;
}
static bool http_port(uint16_t p) {
    return p == 80 || p == 8000 || p == 8080 || p == 8888 || p == 9200 || p == 443 || p == 8443;
}
static std::string clean(const char *data, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) {
        auto c = static_cast<unsigned char>(data[i]);
        out += ((c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t') ? static_cast<char>(c)
                                                                              : '.';
    }
    return out;
}
static std::string request(const Host &h) {
    std::string host = h.input;
    // HTTP Host and TLS SNI are derived only from validated resolved target text.
    if (host.find_first_of("\r\n\t /\\") != std::string::npos)
        host = h.address;
    if (h.family == AF_INET6 && host.find(':') != std::string::npos)
        host = "[" + host + "]";
    return "HEAD / HTTP/1.0\r\nHost: " + host +
           "\r\nUser-Agent: AstraScan/0.1.0\r\nConnection: close\r\n\r\n";
}
#ifdef ASTRA_TLS
static bool tls_wait(SSL *ssl, int rc, int fd, Clock::time_point deadline) {
    int e = SSL_get_error(ssl, rc);
    return (e == SSL_ERROR_WANT_READ && ready(fd, POLLIN, deadline)) ||
           (e == SSL_ERROR_WANT_WRITE && ready(fd, POLLOUT, deadline));
}
static void inspect_tls(int fd, const Host &h, const Config &c, Result &r, SSL_CTX *ctx) {
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx), SSL_free);
    if (!ssl) {
        r.error = "TLS allocation failed";
        return;
    }
    SSL_set_fd(ssl.get(), fd);
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, h.input.c_str(), &v4) != 1 &&
        inet_pton(AF_INET6, h.input.c_str(), &v6) != 1)
        SSL_set_tlsext_host_name(ssl.get(), h.input.c_str());
    auto deadline = Clock::now() + std::chrono::milliseconds(c.timeout_ms);
    int rc;
    while ((rc = SSL_connect(ssl.get())) != 1) {
        if (!tls_wait(ssl.get(), rc, fd, deadline)) {
            r.error = "TLS handshake failed or timed out";
            return;
        }
    }
    r.tls_handshake = true;
    r.tls_protocol = SSL_get_version(ssl.get());
    r.tls_cipher = SSL_get_cipher_name(ssl.get());
    std::unique_ptr<X509, decltype(&X509_free)> cert(SSL_get1_peer_certificate(ssl.get()),
                                                     X509_free);
    if (cert) {
        char b[2048];
        X509_NAME_oneline(X509_get_subject_name(cert.get()), b, sizeof b);
        r.tls_subject = clean(b, std::strlen(b));
        X509_NAME_oneline(X509_get_issuer_name(cert.get()), b, sizeof b);
        r.tls_issuer = clean(b, std::strlen(b));
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            ASN1_TIME_print(bio, X509_get0_notAfter(cert.get()));
            char *p = nullptr;
            long n = BIO_get_mem_data(bio, &p);
            if (n > 0)
                r.tls_expiry = std::string(p, static_cast<size_t>(n));
            BIO_free(bio);
        }
    }
    if (c.http && (r.port == 443 || r.port == 8443)) {
        auto req = request(h);
        size_t sent = 0;
        deadline = Clock::now() + std::chrono::milliseconds(c.timeout_ms);
        while (sent < req.size()) {
            rc = SSL_write(ssl.get(), req.data() + sent, static_cast<int>(req.size() - sent));
            if (rc > 0)
                sent += static_cast<size_t>(rc);
            else if (!tls_wait(ssl.get(), rc, fd, deadline))
                return;
        }
        char b[2048];
        deadline = Clock::now() + std::chrono::milliseconds(c.timeout_ms);
        while ((rc = SSL_read(ssl.get(), b, sizeof b)) <= 0)
            if (!tls_wait(ssl.get(), rc, fd, deadline))
                return;
        r.evidence = clean(b, static_cast<size_t>(rc));
        if (r.evidence.rfind("HTTP/", 0) == 0)
            r.service = "https";
    }
}
#endif
struct RateLimiter {
    std::mutex mutex;
    Clock::time_point next = Clock::now();
    bool wait(unsigned rate) {
        Clock::time_point slot;
        {
            std::lock_guard lock(mutex);
            slot = std::max(next, Clock::now());
            next = slot + std::chrono::nanoseconds(1000000000ull / rate);
        }
        while (!interrupted && Clock::now() < slot)
            std::this_thread::sleep_for(std::min(
                slot - Clock::now(),
                std::chrono::duration_cast<Clock::duration>(std::chrono::milliseconds(20))));
        return !interrupted;
    }
};
static int connect_to(int fd, const Host &h, uint16_t port, unsigned timeout) {
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
        std::string ip = h.address;
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
    if (!ready(fd, POLLOUT, Clock::now() + std::chrono::milliseconds(timeout)))
        return interrupted ? EINTR : ETIMEDOUT;
    int error = 0;
    socklen_t size = sizeof error;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0)
        return errno;
    return error;
}
Report scan(const Config &c, const std::vector<Host> &hosts) {
    Report report;
    report.planned = hosts.size() * c.ports.size();
    auto start = Clock::now();
    auto now = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&now, &tm);
    std::ostringstream timestamp;
    timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    report.started_at = timestamp.str();
    std::atomic<size_t> index{0};
    std::mutex results_mutex;
    RateLimiter limiter;
#ifdef ASTRA_TLS
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(
        c.tls ? SSL_CTX_new(TLS_client_method()) : nullptr, SSL_CTX_free);
    if (c.tls && !ctx)
        throw std::runtime_error("could not initialize OpenSSL");
#endif
    auto worker = [&]() {
        while (!interrupted) {
            size_t i = index.fetch_add(1);
            if (i >= report.planned)
                break;
            const auto &h = hosts[i / c.ports.size()];
            Result r;
            r.target = h.input;
            r.address = h.address;
            r.port = c.ports[i % c.ports.size()];
            r.service = service(r.port);
            for (unsigned attempt = 0; attempt <= c.retries && !interrupted; ++attempt) {
                if (!limiter.wait(c.rate))
                    break;
                ++r.attempts;
                Socket socket(::socket(h.family, SOCK_STREAM, 0));
                int error = 0;
                auto t = Clock::now();
                if (socket.fd < 0)
                    error = errno;
                else {
                    int flags = fcntl(socket.fd, F_GETFL, 0);
                    if (flags < 0 || fcntl(socket.fd, F_SETFL, flags | O_NONBLOCK) < 0)
                        error = errno;
                    else
                        error = connect_to(socket.fd, h, r.port, c.timeout_ms);
                }
                r.latency_ms = std::chrono::duration<double, std::milli>(Clock::now() - t).count();
                if (interrupted)
                    break;
                if (error == 0) {
                    r.state = "open";
                    r.error.clear();
#ifdef ASTRA_TLS
                    if (c.tls && tls_port(r.port))
                        inspect_tls(socket.fd, h, c, r, ctx.get());
                    else
#endif
                        if (!tls_port(r.port) && ((c.http && http_port(r.port)) || c.services)) {
                        if (c.http && http_port(r.port)) {
                            auto req = request(h);
                            size_t sent = 0;
                            auto deadline = Clock::now() + std::chrono::milliseconds(c.timeout_ms);
                            while (sent < req.size() && !interrupted) {
                                ssize_t n =
                                    send(socket.fd, req.data() + sent, req.size() - sent, 0);
                                if (n > 0)
                                    sent += static_cast<size_t>(n);
                                else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
                                         ready(socket.fd, POLLOUT, deadline))
                                    continue;
                                else
                                    break;
                            }
                        }
                        if (ready(socket.fd, POLLIN,
                                  Clock::now() + std::chrono::milliseconds(c.timeout_ms))) {
                            char b[2048];
                            ssize_t n = recv(socket.fd, b, sizeof b, 0);
                            if (n > 0)
                                r.evidence = clean(b, static_cast<size_t>(n));
                            if (r.evidence.rfind("SSH-", 0) == 0)
                                r.service = "ssh";
                            else if (r.evidence.rfind("HTTP/", 0) == 0)
                                r.service = "http";
                            else if (r.evidence.rfind("RFB ", 0) == 0)
                                r.service = "vnc";
                        }
                    }
                    break;
                }
                r.error = std::strerror(error);
                r.state = error == ECONNREFUSED ? "closed"
                          : error == ETIMEDOUT  ? "filtered"
                                                : "error";
                if (r.state == "closed")
                    break;
            }
            if (!r.state.empty() && !interrupted) {
                std::lock_guard lock(results_mutex);
                report.results.push_back(std::move(r));
            }
        }
    };
    std::vector<std::thread> threads;
    try {
        for (size_t i = 0; i < std::min<size_t>(c.workers, report.planned); ++i)
            threads.emplace_back(worker);
    } catch (...) {
        interrupted = 1;
        for (auto &t : threads)
            t.join();
        throw;
    }
    for (auto &t : threads)
        t.join();
    std::sort(report.results.begin(), report.results.end(), [](const auto &a, const auto &b) {
        return a.address == b.address ? a.port < b.port : a.address < b.address;
    });
    report.cancelled = interrupted != 0;
    report.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
    return report;
}
} // namespace astra

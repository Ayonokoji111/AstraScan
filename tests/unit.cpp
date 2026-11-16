#include "astra/astra.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
using namespace astra;
int checks = 0;
void check(bool v, const char *message) {
    ++checks;
    if (!v)
        throw std::runtime_error(message);
}
void rejects(const std::function<void()> &f) {
    bool rejected = false;
    try {
        f();
    } catch (const std::exception &) {
        rejected = true;
    }
    check(rejected, "expected rejection");
}
int main() {
    try {
        check(parse_ports("443,22,80-82,80") == std::vector<uint16_t>({22, 80, 81, 82, 443}),
              "range sorting/dedup");
        check(parse_ports("1-65535").size() == 65535, "full port range");
        for (const auto *s :
             {"", "0", "65536", "22,", "22,,80", "-1", "1-0", "3-1", "1-2-3", "1x", " 80", "+80"})
            rejects([&] { parse_ports(s); });
        check(number("0", 0, 5, "retry") == 0, "zero integer");
        rejects([] { number("99999999999999999", 0, 100, "overflow"); });
        Config c;
        c.targets = {"127.0.0.3/30"};
        c.ports = {80};
        auto h = resolve_targets(c);
        check(h.size() == 4, "CIDR includes all addresses");
        check(h[0].address == "127.0.0.0", "CIDR normalization");
        c.excludes = {"127.0.0.1/32", "127.0.0.2"};
        h = resolve_targets(c);
        check(h.size() == 2, "CIDR exclusions");
        c.targets = {"127.0.0.1", "127.0.0.1"};
        c.excludes.clear();
        check(resolve_targets(c).size() == 1, "target dedup");
        c.targets = {"127.0.0.0/0"};
        rejects([&] { resolve_targets(c); });
        c.targets = {"::1/128"};
        rejects([&] { resolve_targets(c); });
        c.targets = {"127.0.0.1/33"};
        rejects([&] { resolve_targets(c); });
        c.targets = {"127.0.0.1"};
        c.excludes = c.targets;
        rejects([&] { resolve_targets(c); });
        check(json_escape("\"\\\n\x01") == "\"\\\"\\\\\\n\\u0001\"", "JSON escaping");
        check(html_escape("<script>&\"'") == "&lt;script&gt;&amp;&quot;&#39;", "HTML escaping");
        Report report;
        Result r;
        r.target = "=cmd";
        r.address = "127.0.0.1";
        r.port = 22;
        r.state = "open";
        r.evidence = "<script>alert(1)</script>";
        report.results = {r};
        report.planned = 1;
        c.format = "html";
        auto out = render(c, report);
        check(out.find("<script>") == std::string::npos, "HTML evidence escaped");
        c.format = "csv";
        check(render(c, report).find("\"'=cmd\"") != std::string::npos, "CSV formula escaped");
        c.format = "json";
        check(render(c, report).find("\"verified\": false") != std::string::npos,
              "TLS trust explicit");
        Result http;
        http.evidence = "HTTP/1.1 204 No Content\r\nSeRvEr: fixture\r\nSet-Cookie: "
                        "a=1\r\nSet-Cookie: b=2\r\n\r\n";
        parse_http(http);
        check(http.http_status == 204 && http.http_headers_complete,
              "HTTP status and completeness");
        check(http.http_headers.size() == 3 && http.http_headers[0].first == "server",
              "HTTP duplicate headers and normalization");
        http.evidence = "HTTP/1.1 200 OK\r\nServer: incomplete";
        parse_http(http);
        check(!http.http_headers_complete && http.http_headers.empty(),
              "incomplete last field omitted");
        http.evidence = "HTTP/fake 200 OK\r\n\r\n";
        parse_http(http);
        check(http.http_status == 0, "invalid HTTP version");
        http.evidence = "HTTP/1.1 200evil\r\n\r\n";
        parse_http(http);
        check(http.http_status == 0, "invalid HTTP status delimiter");
        http.evidence = "HTTP/1.1 200 OK\r\nBad Name: ignored\r\nValid: ok\r\n\r\n";
        parse_http(http);
        check(http.http_headers.size() == 1, "invalid field name ignored");
        report.results[0].tls_handshake = true;
        report.results[0].tls_verification_attempted = true;
        report.results[0].tls_verified = false;
        report.results[0].tls_verification_error = "<untrusted>";
        c.format = "html";
        check(render(c, report).find("&lt;untrusted&gt;") != std::string::npos,
              "TLS verification evidence HTML escaping");
        report.results[0].transport = "udp";
        report.results[0].state = "open|filtered";
        c.format = "json";
        check(render(c, report).find("open|filtered") != std::string::npos,
              "UDP ambiguous state serialized");
        std::cout << checks << " unit checks passed\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}

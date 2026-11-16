#include "astra/astra.hpp"
#include <iomanip>
#include <map>
#include <sstream>
namespace astra {
std::string json_escape(const std::string &s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : s)
        switch (c) {
        case '"':
            o << "\\\"";
            break;
        case '\\':
            o << "\\\\";
            break;
        case '\n':
            o << "\\n";
            break;
        case '\r':
            o << "\\r";
            break;
        case '\t':
            o << "\\t";
            break;
        default:
            if (c < 32 || c >= 127)
                o << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(c) << std::dec;
            else
                o << static_cast<char>(c);
        }
    return o.str() + '"';
}
std::string html_escape(const std::string &s) {
    std::string out;
    for (char c : s)
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        default:
            out += c;
        }
    return out;
}
static std::string csv(const std::string &s) {
    std::string out = "\"";
    auto first = s.find_first_not_of(" \t\r\n");
    if (first != std::string::npos &&
        (s[first] == '=' || s[first] == '+' || s[first] == '-' || s[first] == '@'))
        out += '\'';
    for (char c : s) {
        if (c == '"')
            out += '"';
        out += c;
    }
    return out + '"';
}
static std::string one_line(const std::string &s) {
    std::string out;
    for (unsigned char c : s)
        out += c >= 32 && c < 127 ? static_cast<char>(c) : ' ';
    return out;
}
static const char *boolean(bool b) {
    return b ? "true" : "false";
}
static void strings(std::ostream &out, const std::vector<std::string> &values) {
    out << '[';
    bool first = true;
    for (const auto &value : values) {
        if (!first)
            out << ',';
        first = false;
        out << json_escape(value);
    }
    out << ']';
}
static void ports(std::ostream &out, const std::vector<uint16_t> &values) {
    out << '[';
    bool first = true;
    for (auto value : values) {
        if (!first)
            out << ',';
        first = false;
        out << value;
    }
    out << ']';
}
static void result_json(std::ostream &o, const Result &r) {
    o << "{\"target\": " << json_escape(r.target) << ", \"address\": " << json_escape(r.address)
      << ", \"port\": " << r.port << ", \"transport\": " << json_escape(r.transport)
      << ", \"state\": " << json_escape(r.state) << ", \"latency_ms\": " << r.latency_ms
      << ", \"attempts\": " << r.attempts << ", \"service\": " << json_escape(r.service)
      << ", \"service_source\": " << json_escape(r.service_source)
      << ", \"response_bytes\": " << r.response_bytes
      << ", \"evidence\": " << json_escape(r.evidence) << ", \"error\": " << json_escape(r.error)
      << ", \"tls\": {\"handshake\": " << boolean(r.tls_handshake)
      << ", \"verified\": " << boolean(r.tls_verified)
      << ", \"verification_attempted\": " << boolean(r.tls_verification_attempted)
      << ", \"verification_error\": " << json_escape(r.tls_verification_error)
      << ", \"protocol\": " << json_escape(r.tls_protocol)
      << ", \"cipher\": " << json_escape(r.tls_cipher)
      << ", \"subject\": " << json_escape(r.tls_subject)
      << ", \"issuer\": " << json_escape(r.tls_issuer)
      << ", \"not_after\": " << json_escape(r.tls_expiry)
      << ", \"sha256\": " << json_escape(r.tls_sha256) << ", \"sans\": ";
    strings(o, r.tls_sans);
    o << "}, \"http\": {\"status\": " << r.http_status
      << ", \"headers_complete\": " << boolean(r.http_headers_complete) << ", \"headers\": [";
    bool first = true;
    for (const auto &[name, value] : r.http_headers) {
        if (!first)
            o << ',';
        first = false;
        o << "{\"name\":" << json_escape(name) << ",\"value\":" << json_escape(value) << '}';
    }
    o << "]}}";
}
static std::string trust(const Result &r) {
    if (!r.tls_verification_attempted)
        return "not checked";
    return r.tls_verified ? "verified" : ("FAILED: " + r.tls_verification_error);
}
std::string render(const Config &c, const Report &report) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(3);
    std::map<std::string, size_t> counts{
        {"open", 0}, {"closed", 0}, {"filtered", 0}, {"open|filtered", 0}, {"error", 0}};
    for (const auto &r : report.results)
        ++counts[r.state];
    if (c.format == "json") {
        o << "{\n  \"schema_version\": 2,\n  \"scanner\": \"AstraScan\",\n  \"version\": "
          << json_escape(version) << ",\n  \"started_at\": " << json_escape(report.started_at)
          << ",\n  \"elapsed_ms\": " << report.elapsed_ms
          << ",\n  \"cancelled\": " << boolean(report.cancelled)
          << ",\n  \"timed_out\": " << boolean(report.timed_out)
          << ",\n  \"planned\": " << report.planned
          << ",\n  \"completed\": " << report.results.size()
          << ",\n  \"only_open\": " << boolean(c.only_open)
          << ",\n  \"scope\": {\"transport\": " << json_escape(c.transport) << ", \"addresses\": ";
        std::vector<std::string> addresses;
        for (const auto &h : report.hosts)
            addresses.push_back(h.address);
        strings(o, addresses);
        o << ", \"ports\": ";
        ports(o, c.ports);
        o << "},\n  \"configuration\": {\"workers\": " << c.workers << ", \"rate\": " << c.rate
          << ", \"timeout_ms\": " << c.timeout_ms << ", \"retries\": " << c.retries
          << ", \"deadline_ms\": " << c.deadline_ms << ", \"services\": " << boolean(c.services)
          << ", \"tls\": " << boolean(c.tls) << ", \"verify_tls\": " << boolean(c.verify_tls)
          << ", \"http\": " << boolean(c.http)
          << ", \"server_name\": " << json_escape(c.server_name)
          << ", \"udp_payload_bytes\": " << c.udp_payload.size() << ", \"tls_ports\": ";
        ports(o, c.tls_ports);
        o << ", \"http_ports\": ";
        ports(o, c.http_ports);
        o << "},\n  \"summary\": {";
        bool first = true;
        for (const auto &[state, count] : counts) {
            if (!first)
                o << ',';
            first = false;
            o << json_escape(state) << ':' << count;
        }
        o << "},\n  \"results\": [";
        first = true;
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            if (!first)
                o << ',';
            first = false;
            o << "\n    ";
            result_json(o, r);
        }
        o << "\n  ]\n}\n";
    } else if (c.format == "csv") {
        o << "target,address,port,transport,state,latency_ms,attempts,service,evidence,tls_"
             "protocol,tls_subject,tls_not_after,tls_verification_attempted,tls_verified,tls_"
             "verification_error,tls_sha256,http_status,http_headers_complete,error\r\n";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << csv(r.target) << ',' << csv(r.address) << ',' << r.port << ',' << csv(r.transport)
              << ',' << csv(r.state) << ',' << r.latency_ms << ',' << r.attempts << ','
              << csv(r.service) << ',' << csv(r.evidence) << ',' << csv(r.tls_protocol) << ','
              << csv(r.tls_subject) << ',' << csv(r.tls_expiry) << ','
              << boolean(r.tls_verification_attempted) << ',' << boolean(r.tls_verified) << ','
              << csv(r.tls_verification_error) << ',' << csv(r.tls_sha256) << ',' << r.http_status
              << ',' << boolean(r.http_headers_complete) << ',' << csv(r.error) << "\r\n";
        }
    } else if (c.format == "html") {
        o << R"(<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>AstraScan report</title><style>body{font:15px system-ui;background:#0b1220;color:#e6edf7;margin:32px}h1{color:#57dbbd}table{border-collapse:collapse;width:100%;margin-top:24px}td,th{padding:12px;border-bottom:1px solid #2c3b50;text-align:left;vertical-align:top}th{color:#9eb2cc}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:50vw}details{max-width:60vw}code{color:#57dbbd}.summary{display:flex;flex-wrap:wrap;gap:12px}.card{padding:16px;background:#152339;border-radius:10px}.partial{color:#ffce82}</style><h1>AstraScan <small>network inventory</small></h1><p>)"
          << html_escape(report.started_at) << " &middot; " << report.elapsed_ms << " ms &middot; "
          << report.results.size() << " / " << report.planned
          << " tasks</p><div class=\"summary\">";
        for (const auto &[state, count] : counts)
            o << "<div class=\"card\"><strong>" << count << "</strong> " << html_escape(state)
              << "</div>";
        o << "</div>";
        if (report.cancelled || report.timed_out)
            o << "<p class=\"partial\">Partial report: "
              << (report.cancelled ? "cancelled" : "scan deadline reached") << ".</p>";
        o << "<p>Service names are port hints unless banner-confirmed. UDP silence is "
             "inconclusive. TLS trust is checked only when explicitly "
             "requested.</p><table><thead><tr><th>Address / "
             "target</th><th>Endpoint</th><th>State</th><th>Service</th><th>Latency "
             "ms</th><th>Evidence</th></tr></thead><tbody>";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << "<tr><td>" << html_escape(r.address) << "<br><small>" << html_escape(r.target)
              << "</small></td><td>" << r.port << '/' << html_escape(r.transport) << "</td><td>"
              << html_escape(r.state) << "</td><td>" << html_escape(r.service) << "<br><small>"
              << html_escape(r.service_source) << "</small></td><td>" << r.latency_ms
              << "</td><td><details><summary>Details</summary><pre>" << html_escape(r.evidence)
              << "\n"
              << html_escape(r.error);
            if (r.tls_handshake) {
                o << "\nTLS: " << html_escape(r.tls_protocol) << ' ' << html_escape(r.tls_cipher)
                  << "\nSubject: " << html_escape(r.tls_subject)
                  << "\nIssuer: " << html_escape(r.tls_issuer)
                  << "\nExpires: " << html_escape(r.tls_expiry)
                  << "\nTrust: " << html_escape(trust(r))
                  << "\nSHA-256: " << html_escape(r.tls_sha256);
                for (const auto &san : r.tls_sans)
                    o << "\nSAN: " << html_escape(san);
            }
            if (r.http_status)
                o << "\nHTTP status: " << r.http_status
                  << "; headers complete: " << boolean(r.http_headers_complete);
            o << "</pre></details></td></tr>";
        }
        o << "</tbody></table><p>Generated by AstraScan " << version << "</p></html>\n";
    } else {
        o << "AstraScan " << version << " | " << report.started_at << "\n"
          << std::left << std::setw(40) << "ADDRESS" << std::setw(13) << "ENDPOINT" << std::setw(16)
          << "STATE" << std::setw(15) << "SERVICE*" << "LATENCY MS\n";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << std::setw(40) << one_line(r.address) << std::setw(13)
              << (std::to_string(r.port) + "/" + r.transport) << std::setw(16) << r.state
              << std::setw(15) << r.service << r.latency_ms << '\n';
            if (!r.evidence.empty())
                o << "  banner: " << one_line(r.evidence.substr(0, 160)) << '\n';
            if (r.tls_handshake)
                o << "  TLS: " << one_line(r.tls_protocol) << " | " << one_line(r.tls_subject)
                  << " | expires " << one_line(r.tls_expiry) << " | trust: " << one_line(trust(r))
                  << "\n  SHA-256: " << r.tls_sha256 << '\n';
            if (r.http_status)
                o << "  HTTP: " << r.http_status
                  << " | complete headers: " << boolean(r.http_headers_complete) << '\n';
            if (!r.error.empty())
                o << "  note: " << one_line(r.error) << '\n';
        }
        o << '\n' << report.results.size() << '/' << report.planned << " completed";
        for (const auto &[state, count] : counts)
            o << " | " << count << ' ' << state;
        o << " | " << report.elapsed_ms
          << " ms\n* Service labels are port hints unless a banner was recognized. UDP silence is "
             "inconclusive.\n";
        if (report.cancelled)
            o << "Cancelled: partial results.\n";
        if (report.timed_out)
            o << "Scan deadline reached: partial results.\n";
    }
    return o.str();
}
} // namespace astra

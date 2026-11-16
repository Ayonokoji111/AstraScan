#include "astra/astra.hpp"
#include <iomanip>
#include <map>
#include <sstream>
namespace astra {
std::string json_escape(const std::string &s) {
    std::ostringstream o;
    o << '"';
    for (unsigned char c : s) {
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
    std::string o = "\"";
    // Spreadsheet applications may execute cells beginning with formula markers.
    auto first = s.find_first_not_of(" \t\r\n");
    if (first != std::string::npos &&
        (s[first] == '=' || s[first] == '+' || s[first] == '-' || s[first] == '@'))
        o += '\'';
    for (char c : s) {
        if (c == '"')
            o += '"';
        o += c;
    }
    return o + '"';
}
static std::string one_line(const std::string &s) {
    std::string o;
    for (unsigned char c : s)
        o += c >= 32 && c < 127 ? static_cast<char>(c) : ' ';
    return o;
}
std::string render(const Config &c, const Report &report) {
    std::ostringstream o;
    o << std::fixed << std::setprecision(3);
    std::map<std::string, size_t> counts{{"open", 0}, {"closed", 0}, {"filtered", 0}, {"error", 0}};
    for (const auto &r : report.results)
        ++counts[r.state];
    if (c.format == "json") {
        o << "{\n  \"schema_version\": 1,\n  \"scanner\": \"AstraScan\",\n  \"version\": "
          << json_escape(version) << ",\n  \"started_at\": " << json_escape(report.started_at)
          << ",\n  \"elapsed_ms\": " << report.elapsed_ms
          << ",\n  \"cancelled\": " << (report.cancelled ? "true" : "false")
          << ",\n  \"planned\": " << report.planned
          << ",\n  \"completed\": " << report.results.size()
          << ",\n  \"only_open\": " << (c.only_open ? "true" : "false")
          << ",\n  \"summary\": {\"open\": " << counts["open"]
          << ", \"closed\": " << counts["closed"] << ", \"filtered\": " << counts["filtered"]
          << ", \"error\": " << counts["error"] << "},\n  \"results\": [";
        bool first = true;
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            if (!first)
                o << ',';
            first = false;
            o << "\n    {\"target\": " << json_escape(r.target)
              << ", \"address\": " << json_escape(r.address) << ", \"port\": " << r.port
              << ", \"transport\": \"tcp\", \"state\": " << json_escape(r.state)
              << ", \"latency_ms\": " << r.latency_ms << ", \"attempts\": " << r.attempts
              << ", \"service\": " << json_escape(r.service) << ", \"service_source\": "
              << json_escape(r.evidence.rfind("SSH-", 0) == 0 ||
                                     r.evidence.rfind("HTTP/", 0) == 0 ||
                                     r.evidence.rfind("RFB ", 0) == 0
                                 ? "banner"
                                 : "port_hint")
              << ", \"evidence\": " << json_escape(r.evidence)
              << ", \"error\": " << json_escape(r.error)
              << ", \"tls\": {\"handshake\": " << (r.tls_handshake ? "true" : "false")
              << ", \"verified\": false, \"protocol\": " << json_escape(r.tls_protocol)
              << ", \"cipher\": " << json_escape(r.tls_cipher)
              << ", \"subject\": " << json_escape(r.tls_subject)
              << ", \"issuer\": " << json_escape(r.tls_issuer)
              << ", \"not_after\": " << json_escape(r.tls_expiry) << "}}";
        }
        o << "\n  ]\n}\n";
    } else if (c.format == "csv") {
        o << "target,address,port,transport,state,latency_ms,attempts,service,evidence,tls_"
             "protocol,tls_subject,tls_not_after,error\r\n";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << csv(r.target) << ',' << csv(r.address) << ',' << r.port << ",tcp," << csv(r.state)
              << ',' << r.latency_ms << ',' << r.attempts << ',' << csv(r.service) << ','
              << csv(r.evidence) << ',' << csv(r.tls_protocol) << ',' << csv(r.tls_subject) << ','
              << csv(r.tls_expiry) << ',' << csv(r.error) << "\r\n";
        }
    } else if (c.format == "html") {
        o << R"(<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>AstraScan report</title><style>body{font:15px system-ui;background:#0b1220;color:#e6edf7;margin:32px}h1{color:#57dbbd}table{border-collapse:collapse;width:100%;margin-top:24px}td,th{padding:12px;border-bottom:1px solid #2c3b50;text-align:left}th{color:#9eb2cc}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:50vw}.open{color:#57dbbd}.closed{color:#a6b3c7}.filtered,.error{color:#ffce82}details{max-width:60vw}code{color:#57dbbd}</style><h1>AstraScan <small>network inventory</small></h1><p>)"
          << html_escape(report.started_at) << " &middot; " << report.elapsed_ms << " ms &middot; "
          << report.results.size() << " / " << report.planned
          << " tasks</p><p>Open: " << counts["open"] << " &middot; Closed: " << counts["closed"]
          << " &middot; Filtered: " << counts["filtered"] << " &middot; Errors: " << counts["error"]
          << "</p>";
        if (report.cancelled)
            o << "<p>Cancelled: this report is partial.</p>";
        o << "<p>Service names are port hints unless recognized from a banner. TLS certificates "
             "are collected without trust verification.</p><table><thead><tr><th>Address / "
             "target</th><th>Port</th><th>State</th><th>Service</th><th>Connect "
             "ms</th><th>Evidence</th></tr></thead><tbody>";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << "<tr><td>" << html_escape(r.address) << "<br><small>" << html_escape(r.target)
              << "</small></td><td>" << r.port << "/tcp</td><td class=\"" << html_escape(r.state)
              << "\">" << html_escape(r.state) << "</td><td>" << html_escape(r.service)
              << "</td><td>" << r.latency_ms << "</td><td><details><summary>Details</summary><pre>"
              << html_escape(r.evidence) << "\n"
              << html_escape(r.error);
            if (r.tls_handshake)
                o << "\nTLS: " << html_escape(r.tls_protocol) << " " << html_escape(r.tls_cipher)
                  << "\nSubject: " << html_escape(r.tls_subject)
                  << "\nIssuer: " << html_escape(r.tls_issuer)
                  << "\nExpires: " << html_escape(r.tls_expiry) << "\nTrust: not verified";
            o << "</pre></details></td></tr>";
        }
        o << "</tbody></table><p>Generated by AstraScan " << version << "</p></html>\n";
    } else {
        o << "AstraScan " << version << " | " << report.started_at << "\n"
          << std::left << std::setw(40) << "ADDRESS" << std::setw(9) << "PORT" << std::setw(11)
          << "STATE" << std::setw(15) << "SERVICE*" << "CONNECT MS\n";
        for (const auto &r : report.results) {
            if (c.only_open && r.state != "open")
                continue;
            o << std::setw(40) << one_line(r.address) << std::setw(9) << r.port << std::setw(11)
              << r.state << std::setw(15) << r.service << r.latency_ms << '\n';
            if (!r.evidence.empty())
                o << "  banner: " << one_line(r.evidence.substr(0, 160)) << '\n';
            if (r.tls_handshake)
                o << "  TLS: " << one_line(r.tls_protocol) << " | " << one_line(r.tls_subject)
                  << " | expires " << one_line(r.tls_expiry) << " (trust not verified)\n";
            if (!r.error.empty())
                o << "  note: " << one_line(r.error) << '\n';
        }
        o << "\n"
          << report.results.size() << '/' << report.planned << " completed | " << counts["open"]
          << " open | " << counts["closed"] << " closed | " << counts["filtered"] << " filtered | "
          << counts["error"] << " errors | " << report.elapsed_ms
          << " ms\n* Service labels are port hints unless a banner was recognized.\n";
        if (report.cancelled)
            o << "Cancelled: partial results.\n";
    }
    return o.str();
}
} // namespace astra

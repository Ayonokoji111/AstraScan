#include "astra/astra.hpp"
#include <algorithm>
#include <charconv>
#include <sstream>
namespace astra {
void parse_http(Result &r) {
    r.http_headers.clear();
    r.http_status = 0;
    r.http_headers_complete = false;
    if (r.evidence.rfind("HTTP/", 0) != 0)
        return;
    auto end = r.evidence.find("\r\n\r\n");
    r.http_headers_complete = end != std::string::npos;
    auto text = r.evidence.substr(0, end);
    std::istringstream input(text);
    std::string line;
    if (!std::getline(input, line))
        return;
    auto space = line.find(' ');
    if (space == std::string::npos || line.size() < space + 4)
        return;
    auto protocol = line.substr(0, space);
    if (protocol != "HTTP/1.0" && protocol != "HTTP/1.1")
        return;
    if (line.size() > space + 4 && line[space + 4] != ' ' && line[space + 4] != '\r')
        return;
    int status = 0;
    auto [last, ec] = std::from_chars(line.data() + space + 1, line.data() + space + 4, status);
    if (ec != std::errc{} || last != line.data() + space + 4 || status < 100 || status > 599)
        return;
    r.http_status = status;
    while (std::getline(input, line) && r.http_headers.size() < 100) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break;
        // Ignore a trailing incomplete header when the read reached its bound/deadline.
        if (input.eof() && !r.http_headers_complete)
            break;
        auto colon = line.find(':');
        if (colon == std::string::npos || colon == 0)
            continue;
        auto name = line.substr(0, colon);
        if (name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~") !=
            std::string::npos)
            continue;
        std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
        });
        auto start = line.find_first_not_of(" \t", colon + 1);
        auto value = start == std::string::npos ? "" : line.substr(start);
        auto trim = value.find_last_not_of(" \t");
        if (trim != std::string::npos)
            value.resize(trim + 1);
        r.http_headers.emplace_back(std::move(name), std::move(value));
    }
    r.service = r.tls_handshake ? "https" : "http";
    r.service_source = "banner";
}
} // namespace astra

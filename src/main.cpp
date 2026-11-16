#include "astra/astra.hpp"
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
namespace {
void on_signal(int) {
    astra::interrupted = 1;
}
void write_output(const std::string &path, const std::string &data) {
    if (path.empty()) {
        std::cout << data;
        std::cout.flush();
        if (!std::cout)
            throw std::runtime_error("stdout write failed");
        return;
    }
    // Create the temporary next to the destination for an atomic same-filesystem rename.
    std::string temp = path + ".tmp.XXXXXX";
    int fd = mkstemp(temp.data());
    if (fd < 0)
        throw std::runtime_error("cannot create output temporary: " + path);
    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t n = write(fd, data.data() + offset, data.size() - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            close(fd);
            unlink(temp.c_str());
            throw std::runtime_error("output write failed");
        }
        offset += static_cast<size_t>(n);
    }
    int sync_error = fsync(fd);
    int close_error = close(fd);
    if (sync_error < 0 || close_error < 0) {
        unlink(temp.c_str());
        throw std::runtime_error("output flush failed");
    }
    std::error_code ec;
    std::filesystem::rename(temp, path, ec);
    if (ec) {
        unlink(temp.c_str());
        throw std::runtime_error("cannot replace output: " + ec.message());
    }
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
            std::cout << astra::help();
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--version") {
            std::cout << "AstraScan " << astra::version << " C++20 TCP IPv4 IPv6"
#ifdef ASTRA_TLS
                      << " OpenSSL"
#endif
                      << '\n';
            return 0;
        }
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
        std::signal(SIGPIPE, SIG_IGN);
        const auto c = astra::parse_args(argc, argv);
        const auto hosts = astra::resolve_targets(c);
        if (c.dry_run) {
            std::string plan;
            if (c.format == "json") {
                plan = "{\"dry_run\": true, \"host_count\": " + std::to_string(hosts.size()) +
                       ", \"port_count\": " + std::to_string(c.ports.size()) +
                       ", \"tasks\": " + std::to_string(hosts.size() * c.ports.size()) +
                       ", \"hosts\": [";
                bool first = true;
                for (const auto &h : hosts) {
                    if (!first)
                        plan += ',';
                    first = false;
                    plan += "{\"target\":" + astra::json_escape(h.input) +
                            ",\"address\":" + astra::json_escape(h.address) + "}";
                }
                plan += "]}\n";
            } else {
                plan = "Dry run: " + std::to_string(hosts.size()) + " hosts x " +
                       std::to_string(c.ports.size()) +
                       " TCP ports = " + std::to_string(hosts.size() * c.ports.size()) +
                       " tasks; rate <= " + std::to_string(c.rate) + " starts/s\n";
                for (const auto &h : hosts)
                    plan += h.address + " (" + h.input + ")\n";
            }
            write_output(c.output, plan);
            return astra::interrupted ? 130 : 0;
        }
        const auto report = astra::scan(c, hosts);
        write_output(c.output, astra::render(c, report));
        if (report.cancelled)
            return 130;
        for (const auto &r : report.results)
            if (r.state == "error")
                return 1;
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "astrascan: " << e.what() << '\n';
        return 2;
    }
}

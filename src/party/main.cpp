// pp_party: one computation party (party ID 0 or 1) of the two-party search.
//
// Each process owns only its own TLS keys, its own local input shares, its own
// preprocessing material and its own MP-SPDZ channel state. See
// docs/ARCHITECTURE.md for the session protocol.

#include "common/arguments.hpp"
#include "party/party_server.hpp"

#include <climits>
#include <csignal>
#include <cstdlib>
#include <iostream>

namespace {

using namespace pps;

std::string absolute(const std::string& path) {
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved) == nullptr) {
        throw std::runtime_error("path does not exist: " + path);
    }
    return resolved;
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        const std::size_t end = text.find(separator, start);
        parts.push_back(text.substr(start, end - start));
        if (end == std::string::npos) {
            return parts;
        }
        start = end + 1;
    }
}

void usage() {
    std::cerr
        << "Usage: pp_party --party-id <0|1> --listen <host:port> --peer <host:port>\n"
           "                --mpc-hosts <host0,host1> --mpc-port-base <port>\n"
           "                --pki <dir> --runtime <dir>\n"
           "                [--sessions <n>] [--max-input-timeout-ms <ms>]\n"
           "                [--mpc-timeout-ms <ms>] [--owner-timeout-ms <ms>]\n"
           "                [--stats <file>]\n"
           "                [--test-triple-shortfall <n>]   (fault injection, tests only)\n"
           "  party 0 listens on --peer for party 1's control connection;\n"
           "  party 1 connects to party 0 at --peer.\n";
}


PartyOptions parse_options(const Arguments& arguments) {
    arguments.allow_only({"party-id", "listen", "peer", "mpc-hosts", "mpc-port-base", "pki",
                          "runtime", "sessions", "max-input-timeout-ms", "mpc-timeout-ms",
                          "stats", "owner-timeout-ms", "test-triple-shortfall"});
    PartyOptions options;
    options.party_id = static_cast<int>(arguments.get_uint("party-id"));
    if (options.party_id > 1) {
        throw std::invalid_argument("--party-id must be 0 or 1");
    }
    options.listen = arguments.get("listen");
    options.peer = arguments.get("peer");
    options.mpc_hosts = split(arguments.get("mpc-hosts"), ',');
    if (options.mpc_hosts.size() != 2) {
        throw std::invalid_argument("--mpc-hosts needs exactly two hosts");
    }
    options.mpc_port_base = static_cast<int>(arguments.get_uint("mpc-port-base"));
    options.pki = absolute(arguments.get("pki"));
    options.runtime = absolute(arguments.get("runtime"));
    options.sessions = arguments.get_uint("sessions", 0);
    options.max_input_timeout = Millis(arguments.get_uint("max-input-timeout-ms", 120000));
    options.mpc_timeout = Millis(arguments.get_uint("mpc-timeout-ms", 600000));
    options.owner_timeout = Millis(arguments.get_uint("owner-timeout-ms", 10000));
    if (arguments.has("stats")) {
        const std::string stats = arguments.get("stats");
        options.stats_path = stats.front() == '/' ? stats : absolute(".") + "/" + stats;
    }
    options.test_triple_shortfall = arguments.get_uint("test-triple-shortfall", 0);
    return options;
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    pps::raise_file_descriptor_limit();
    try {
        const pps::Arguments arguments(argc, argv, 1);
        pps::PartyServer(parse_options(arguments)).run();
        return 0;
    } catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << "\n";
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << "\n";
        return 1;
    }
}

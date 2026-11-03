#include "client/client_common.hpp"

#include "common/json.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace pps::client {

Target parse_target(const Arguments& arguments, std::uint64_t default_timeout_ms) {
    Target target;
    target.pki = arguments.get("pki");
    target.parties = {parse_endpoint(arguments.get("party0")),
                      parse_endpoint(arguments.get("party1"))};
    target.session = wire::parse_session_hex(arguments.get("session"));
    target.deadline = Clock::now() + Millis(arguments.get_uint("timeout-ms", default_timeout_ms));
    return target;
}

std::unique_ptr<TlsContext> client_context(const std::string& pki, const std::string& identity) {
    auto context = std::make_unique<TlsContext>(pki_credentials(pki, identity), false);
    if (context->identity() != identity) {
        throw std::runtime_error("certificate identity '" + context->identity() +
                                 "' does not match " + identity);
    }
    return context;
}

std::string aborted_json(const std::string& role, const TransportError& error) {
    return JsonObject()
        .add("role", role)
        .add("status", "aborted")
        .add("code", abort_code_name(error.code()))
        .add("message", error.what())
        .str();
}

std::vector<StationRecord> read_station_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::invalid_argument("cannot read " + path);
    }
    std::vector<StationRecord> records;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::stringstream fields(line);
        std::string id, x, y, radius;
        if (!std::getline(fields, id, ',') || !std::getline(fields, x, ',') ||
            !std::getline(fields, y, ',') || !std::getline(fields, radius, ',')) {
            throw std::invalid_argument("station file lines must be id,x,y,radius");
        }
        records.push_back({parse_u64(id), parse_i64(x), parse_i64(y), parse_u64(radius)});
    }
    return records;
}

}  // namespace pps::client

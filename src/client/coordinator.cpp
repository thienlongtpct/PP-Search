// Coordinator command: opens a session with the public parameters on both
// parties and reports the public result once they agree.

#include "client/client_common.hpp"
#include "client/commands.hpp"
#include "common/json.hpp"

#include <algorithm>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace pps::client {
namespace {

std::vector<std::uint64_t> parse_id_list(const std::string& text) {
    std::vector<std::uint64_t> ids;
    if (text.empty()) {
        return ids;
    }
    std::stringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ',')) {
        ids.push_back(parse_u64(item));
    }
    return ids;
}

wire::SessionOpen parse_session_request(const Arguments& arguments) {
    wire::SessionOpen open;
    const std::uint64_t horizon = arguments.get_uint("horizon");
    if (horizon > kHorizonMax) {
        throw std::invalid_argument("horizon must fit in 32 bits");
    }
    open.horizon = static_cast<std::uint32_t>(horizon);
    open.timeout_ms = static_cast<std::uint32_t>(arguments.get_uint("timeout-ms", 30000));
    open.requester = arguments.get("requester");
    if (arguments.has("stations-file")) {
        for (const StationRecord& record : read_station_file(arguments.get("stations-file"))) {
            open.station_ids.push_back(record.id);
        }
    } else {
        open.station_ids = parse_id_list(arguments.get("stations", ""));
    }
    return open;
}

std::unique_ptr<TlsConnection> connect_with_retry(const Target& target, TlsContext& context, int party) {
    while (true) {
        try {
            return tls_connect(target.parties[party].first, target.parties[party].second, context,
                               wire::party_identity(party),
                               std::min(kConnectTimeout, remaining(target.deadline)));
        } catch (const TimeoutError&) {
        } catch (const PeerClosedError&) {
        }
        if (Clock::now() >= target.deadline) {
            throw TimeoutError("cannot reach party " + std::to_string(party));
        }
        std::this_thread::sleep_for(kRetryDelay);
    }
}

}  // namespace

int run_coordinator(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "horizon", "requester",
                          "stations", "stations-file", "result-timeout-ms",
                          "test-unchecked-station-list"});
    const Target target = parse_target(arguments, 30000);
    wire::SessionOpen open = parse_session_request(arguments);
    if (arguments.get("test-unchecked-station-list", "0") != "1") {
        // Canonical order: ascending station ID; duplicates are rejected.
        std::sort(open.station_ids.begin(), open.station_ids.end());
        if (std::adjacent_find(open.station_ids.begin(), open.station_ids.end()) !=
            open.station_ids.end()) {
            std::cout << JsonObject()
                             .add("role", "coordinator")
                             .add("status", "rejected")
                             .add("code", "duplicate")
                             .add("message", "duplicate station ID in request")
                             .str()
                      << std::endl;
            return 2;
        }
    }

    auto context = client_context(target.pki, wire::kCoordinatorIdentity);
    const auto result_deadline =
        Clock::now() + Millis(open.timeout_ms) + Millis(arguments.get_uint("result-timeout-ms", 600000));
    std::array<std::unique_ptr<TlsConnection>, 2> connections;
    std::array<wire::SessionResult, 2> results;
    try {
        for (std::size_t party = 0; party < 2; ++party) {
            connections[party] = connect_with_retry(target, *context, static_cast<int>(party));
            connections[party]->send(wire::make_frame(wire::MsgType::kSessionOpen, target.session, open),
                                     kConnectTimeout);
        }
        for (std::size_t party = 0; party < 2; ++party) {
            const wire::Frame frame = connections[party]->receive_expect(
                wire::MsgType::kSessionResult, target.session, remaining(result_deadline));
            results[party] = wire::decode_session_result(frame.payload);
        }
    } catch (const TransportError& error) {
        std::cout << aborted_json("coordinator", error) << std::endl;
        return 2;
    }
    if (results[0].match != results[1].match || results[0].station_id != results[1].station_id) {
        std::cout << JsonObject()
                         .add("role", "coordinator")
                         .add("status", "inconsistent")
                         .str()
                  << std::endl;
        return 3;
    }
    JsonObject json;
    json.add("role", "coordinator")
        .add("status", "ok")
        .add("session", wire::session_hex(target.session))
        .add("match", results[0].match);
    if (results[0].match) {
        json.add("station_id", results[0].station_id);
    }
    std::cout << json.str() << std::endl;
    return 0;
}

}  // namespace pps::client

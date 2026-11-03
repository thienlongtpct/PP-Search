// Test-only misbehaving station: sends one kind of malformed or abusive traffic
// so the integration tests can check how a party rejects it.

#include "client/client_common.hpp"
#include "client/commands.hpp"
#include "common/crypto.hpp"
#include "common/json.hpp"

#include <iostream>
#include <stdexcept>
#include <thread>

namespace pps::client {

int run_fault_injection(const Arguments& arguments) {
    arguments.allow_only({"pki", "party0", "party1", "session", "timeout-ms", "id", "kind",
                          "target-party"});
    const Target target = parse_target(arguments, 30000);
    const std::uint64_t id = arguments.get_uint("id");
    const std::string kind = arguments.get("kind");
    const int party = static_cast<int>(arguments.get_uint("target-party", 0));
    auto context = client_context(target.pki, wire::station_identity(id));
    std::unique_ptr<TlsConnection> connection;
    // Wait until the party has opened the session (first frame is valid).
    while (!connection) {
        try {
            connection = tls_connect(target.parties[party].first, target.parties[party].second,
                                     *context, wire::party_identity(party), kConnectTimeout);
        } catch (const TransportError&) {
            if (Clock::now() >= target.deadline) {
                throw;
            }
            std::this_thread::sleep_for(kRetryDelay);
        }
    }
    const auto share = [&](wire::Field field, std::uint64_t station) {
        wire::InputShare value;
        value.owner = wire::OwnerKind::kStation;
        value.field = field;
        value.station_id = station;
        value.share = random_word();
        return wire::make_frame(wire::MsgType::kInputShare, target.session, value);
    };
    const Millis timeout = kConnectTimeout;
    try {
        if (kind == "bad-magic") {
            connection->send_raw_for_test(std::vector<std::uint8_t>(wire::kHeaderSize, 0xAB), timeout);
        } else if (kind == "oversize") {
            wire::Frame frame = share(wire::Field::kX, id);
            auto header = wire::encode_header(frame);
            const std::uint32_t too_large = wire::kMaxPayload + 1;
            for (int i = 0; i < 4; ++i) {
                header[32 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(too_large >> (8 * i));
            }
            connection->send_raw_for_test({header.begin(), header.end()}, timeout);
        } else if (kind == "bad-sequence") {
            connection->set_next_sequence_for_test(7);
            connection->send(share(wire::Field::kX, id), timeout);
        } else if (kind == "duplicate-field") {
            connection->send(share(wire::Field::kX, id), timeout);
            connection->send(share(wire::Field::kX, id), timeout);
        } else if (kind == "wrong-station") {
            connection->send(share(wire::Field::kX, id + 1), timeout);
        } else if (kind == "trailing-bytes") {
            wire::Frame frame = share(wire::Field::kX, id);
            frame.payload.push_back(0);
            connection->send(frame, timeout);
        } else if (kind == "incomplete-done") {
            connection->send(share(wire::Field::kX, id), timeout);
            wire::InputDone done{wire::OwnerKind::kStation, id, 3, {}};
            connection->send(wire::make_frame(wire::MsgType::kInputDone, target.session, done), timeout);
        } else if (kind == "disconnect") {
            connection->send(share(wire::Field::kX, id), timeout);
            connection->close();
            std::cout << JsonObject().add("role", "inject").add("status", "disconnected").str() << std::endl;
            return 0;
        } else if (kind == "stall") {
            connection->send(share(wire::Field::kX, id), timeout);
        } else {
            throw std::invalid_argument("unknown --kind " + kind);
        }
        const wire::Frame reply = connection->receive(remaining(target.deadline));
        if (reply.type == wire::MsgType::kAbort) {
            const wire::Abort abort = wire::decode_abort(reply.payload);
            std::cout << JsonObject()
                             .add("role", "inject")
                             .add("status", "rejected")
                             .add("code", abort_code_name(abort.code))
                             .add("message", abort.message)
                             .str()
                      << std::endl;
            return 0;
        }
        std::cout << JsonObject().add("role", "inject").add("status", "unexpected-reply").str() << std::endl;
        return 1;
    } catch (const TransportError& error) {
        std::cout << JsonObject()
                         .add("role", "inject")
                         .add("status", "connection-ended")
                         .add("code", abort_code_name(error.code()))
                         .add("message", error.what())
                         .str()
                  << std::endl;
        return 0;
    }
}


}  // namespace pps::client

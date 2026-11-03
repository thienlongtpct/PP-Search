#pragma once

// State of one search session on one computation party.

#include "backend/mpspdz_party.hpp"
#include "common/deadline.hpp"
#include "net/tls_transport.hpp"
#include "net/wire.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace pps {

// Ends the current session without ending the process.
class SessionAbort : public std::runtime_error {
public:
    SessionAbort(AbortCode code, const std::string& message, bool from_peer = false)
        : std::runtime_error(message), code(code), from_peer(from_peer) {}
    AbortCode code;
    bool from_peer;
};

// This party's view of one input owner: its shares and, for stations, the open
// connection that later carries the output.
struct OwnerState {
    bool done = false;
    std::array<std::uint8_t, 16> submission_id{};
    std::uint8_t fields = 0;  // bit (field - 1) set when received
    std::unique_ptr<TlsConnection> connection;
    LocalShare x;
    LocalShare y;
    LocalShare radius;
};

struct Session {
    wire::SessionId id{};
    wire::SessionOpen open;
    std::vector<std::uint8_t> open_payload;
    Clock::time_point started = Clock::now();
    Clock::time_point input_deadline;
    std::unique_ptr<TlsConnection> coordinator;
    OwnerState requester;
    std::map<std::uint64_t, OwnerState> stations;  // ascending public ID order
    std::optional<wire::PeerSync> peer_inputs;
    TransportCounters input_traffic;
    TransportCounters output_traffic;
    TransportCounters peer_traffic_start;
    double input_seconds = 0;
    double output_seconds = 0;
    bool output_delivered = false;
    std::string abort_status;  // "aborted:<code>" once the session has aborted
    std::optional<BackendStats> backend;
    std::optional<OperationCounts> plan;
};

}  // namespace pps

#pragma once

// Shared by the pp_client commands.

#include "common/arguments.hpp"
#include "common/deadline.hpp"
#include "net/tls_transport.hpp"
#include "net/wire.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace pps::client {

inline constexpr Millis kConnectTimeout{5000};
inline constexpr Millis kRetryDelay{100};

// The session a command talks to: both parties' endpoints and its deadline.
struct Target {
    std::string pki;
    std::array<std::pair<std::string, int>, 2> parties;
    wire::SessionId session{};
    Clock::time_point deadline;
};

Target parse_target(const Arguments& arguments, std::uint64_t default_timeout_ms);

// TLS context for `identity`, checked against the certificate's common name.
std::unique_ptr<TlsContext> client_context(const std::string& pki, const std::string& identity);

std::string aborted_json(const std::string& role, const TransportError& error);

// One line of a stations file: id,x,y,radius
struct StationRecord {
    std::uint64_t id;
    std::int64_t x;
    std::int64_t y;
    std::uint64_t radius;
};

std::vector<StationRecord> read_station_file(const std::string& path);

}  // namespace pps::client

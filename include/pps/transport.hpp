#pragma once

#include "pps/wire.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace pps {

struct TransportCounters {
    std::uint64_t bytes_sent = 0;
    std::uint64_t bytes_received = 0;
    std::uint64_t messages_sent = 0;
    std::uint64_t messages_received = 0;

    TransportCounters& operator+=(const TransportCounters& other) {
        bytes_sent += other.bytes_sent;
        bytes_received += other.bytes_received;
        messages_sent += other.messages_sent;
        messages_received += other.messages_received;
        return *this;
    }
};

using Millis = std::chrono::milliseconds;

// An authenticated, confidential, ordered message channel to one peer.
// Frames carry a per-direction sequence number that starts at zero and must
// increase by one; any deviation is a ProtocolError. Byte counters include
// frame headers but not TLS record overhead.
class Transport {
public:
    virtual ~Transport() = default;

    virtual void send(wire::Frame frame, Millis timeout) = 0;
    // Throws TimeoutError, PeerClosedError or ProtocolError. Abort frames are
    // returned like any other frame; use receive_expect to turn them into
    // RemoteAbortError.
    virtual wire::Frame receive(Millis timeout) = 0;
    // Authenticated identity (certificate common name) of the peer.
    virtual const std::string& peer_identity() const = 0;
    virtual TransportCounters counters() const = 0;
    virtual void close() = 0;

    // Receives one frame of the given type for the given session.
    wire::Frame receive_expect(wire::MsgType type, const wire::SessionId& session,
                               Millis timeout);
    // Best-effort abort notification; never throws.
    void send_abort_noexcept(const wire::SessionId& session, AbortCode code,
                             const std::string& message) noexcept;
};

}  // namespace pps

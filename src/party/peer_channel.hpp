#pragma once

// Party-to-party control channel. It carries only public agreement messages
// (session and input-set digests, abort notices); MPC traffic uses MP-SPDZ's
// own channel.

#include "net/tls_transport.hpp"
#include "net/wire.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>

namespace pps {

inline constexpr std::uint32_t kSyncSessionOpen = 1;
inline constexpr std::uint32_t kSyncInputsComplete = 2;
inline constexpr std::uint32_t kSyncAbort = 3;

class PeerChannel {
public:
    // Party 0 listens on `endpoint` for party 1's connection; party 1 connects.
    static std::unique_ptr<PeerChannel> establish(int party_id, const std::string& endpoint,
                                                  TlsContext& server_context,
                                                  TlsContext& client_context);

    explicit PeerChannel(std::unique_ptr<TlsConnection> connection)
        : connection_(std::move(connection)) {}

    void send(const wire::SessionId& session, std::uint32_t phase, std::uint8_t status,
              const std::array<std::uint8_t, 32>& digest);

    // Returns the next control message for this session; skips stale frames
    // of earlier sessions. Peer aborts become SessionAbort.
    wire::PeerSync read(const wire::SessionId& session, Millis timeout);

    // Like read, but requires `phase` and turns a timeout into SessionAbort.
    wire::PeerSync expect(const wire::SessionId& session, std::uint32_t phase, Millis timeout);

    bool has_pending_message() { return connection_->wait_readable(Millis(0)); }
    TransportCounters counters() const { return connection_->counters(); }

private:
    std::unique_ptr<TlsConnection> connection_;
};

}  // namespace pps

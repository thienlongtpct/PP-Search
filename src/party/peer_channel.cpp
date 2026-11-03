#include "party/peer_channel.hpp"

#include "party/session.hpp"
#include "party/timeouts.hpp"

#include <iostream>
#include <thread>

namespace pps {

std::unique_ptr<PeerChannel> PeerChannel::establish(int party_id, const std::string& endpoint,
                                                    TlsContext& server_context,
                                                    TlsContext& client_context) {
    const auto [host, port] = parse_endpoint(endpoint);
    const auto deadline = Clock::now() + Millis(120000);
    const std::string identity = wire::party_identity(party_id);
    const std::string expected = wire::party_identity(1 - party_id);
    const auto log = [&identity](const std::string& message) {
        std::cerr << "[" << identity << "] " << message << std::endl;
    };
    std::unique_ptr<TlsConnection> peer;
    if (party_id == 0) {
        TlsListener peer_listener(host, port, server_context);
        while (!peer) {
            if (Clock::now() >= deadline) {
                throw std::runtime_error("party1 did not connect to the control channel");
            }
            try {
                auto connection = peer_listener.accept(remaining(deadline), kHandshakeTimeout);
                if (connection && connection->peer_identity() == expected) {
                    peer = std::move(connection);
                } else if (connection) {
                    log("rejected control connection from " + connection->peer_identity());
                }
            } catch (const TransportError& error) {
                log(std::string("control-channel handshake failed: ") + error.what());
            }
        }
    } else {
        while (!peer) {
            try {
                peer = tls_connect(host, port, client_context, expected, kHandshakeTimeout);
            } catch (const TransportError& error) {
                if (Clock::now() >= deadline) {
                    throw;
                }
                std::this_thread::sleep_for(Millis(200));
            }
        }
    }
    log("control channel to " + expected + " established");
    return std::make_unique<PeerChannel>(std::move(peer));
}

void PeerChannel::send(const wire::SessionId& session, std::uint32_t phase, std::uint8_t status,
                       const std::array<std::uint8_t, 32>& digest) {
    wire::PeerSync sync;
    sync.phase = phase;
    sync.status = status;
    sync.digest = digest;
    connection_->send(wire::make_frame(wire::MsgType::kPeerSync, session, sync), kControlTimeout);
}

wire::PeerSync PeerChannel::read(const wire::SessionId& session, Millis timeout) {
    const auto deadline = Clock::now() + timeout;
    while (true) {
        wire::Frame frame = connection_->receive(remaining(deadline));
        if (frame.type != wire::MsgType::kPeerSync) {
            throw std::runtime_error("unexpected message on control channel");
        }
        const wire::PeerSync sync = wire::decode_peer_sync(frame.payload);
        if (frame.session != session) {
            continue;
        }
        if (sync.status != 0 || sync.phase == kSyncAbort) {
            const auto code = static_cast<AbortCode>(sync.status == 0 ? 7 : sync.status);
            throw SessionAbort(code, std::string("peer party aborted (") +
                                         abort_code_name(code) + ")",
                               true);
        }
        return sync;
    }
}

wire::PeerSync PeerChannel::expect(const wire::SessionId& session, std::uint32_t phase,
                                   Millis timeout) {
    try {
        const wire::PeerSync sync = read(session, timeout);
        if (sync.phase != phase) {
            throw SessionAbort(AbortCode::kPeerMismatch, "peer party is in another phase");
        }
        return sync;
    } catch (const TimeoutError&) {
        throw SessionAbort(AbortCode::kTimeout, "peer party did not respond in time");
    }
}

}  // namespace pps

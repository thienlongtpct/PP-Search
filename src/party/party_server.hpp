#pragma once

// One computation party: accepts sessions from the coordinator and runs each
// through the phases open -> agree -> collect inputs -> compute -> deliver.
// See docs/ARCHITECTURE.md for the session protocol.
//
// Sessions run one at a time on this class. The input and output phases are
// implemented in party_server_inputs.cpp and party_server_outputs.cpp.

#include "backend/mpspdz_party.hpp"
#include "net/tls_transport.hpp"
#include "party/peer_channel.hpp"
#include "party/session.hpp"

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace pps {

struct PartyOptions {
    int party_id = 0;
    std::string listen;
    std::string peer;
    std::vector<std::string> mpc_hosts;
    int mpc_port_base = 0;
    std::string pki;
    std::string runtime;
    std::uint64_t sessions = 0;  // 0 = unlimited
    Millis max_input_timeout{120000};
    Millis mpc_timeout{600000};
    Millis owner_timeout{10000};  // one owner's complete submission
    std::string stats_path;
    std::uint64_t test_triple_shortfall = 0;
};

class PartyServer {
public:
    explicit PartyServer(PartyOptions options);

    void run();

private:
    TlsCredentials credentials() const;
    void log(const std::string& message) const;
    void log_session(const Session& session, const std::string& message) const;

    // Connection intake
    std::unique_ptr<TlsConnection> accept_one(Millis timeout);
    void park(std::unique_ptr<TlsConnection> connection);
    std::unique_ptr<TlsConnection> take_pending_coordinator();
    bool recently_closed(const wire::SessionId& session) const;
    void reject_outside_session(TlsConnection& connection);

    // Session phases
    void serve_session();
    void open_session(Session& session);
    void agree_on_session(Session& session);
    void collect_inputs(Session& session);
    AuthorizedSelection compute(Session& session);
    void deliver(Session& session, const AuthorizedSelection& selection);
    void abort_session(Session& session, AbortCode code, const std::string& reason,
                       bool notify_peer);
    void write_stats(const Session& session, const std::optional<AuthorizedSelection>& selection);

    // Input phase helpers
    void poll_peer(Session& session);
    bool receive_owner_inputs(Session& session, std::unique_ptr<TlsConnection> connection);

    PartyOptions options_;
    std::string identity_;
    TlsContext server_context_;
    TlsContext client_context_;
    TlsListener listener_;
    std::unique_ptr<PeerChannel> peer_;
    std::unique_ptr<MpSpdzParty> backend_;
    std::deque<std::unique_ptr<TlsConnection>> pending_;  // coordinators only
    std::deque<wire::SessionId> closed_sessions_;
    bool fatal_backend_failure_ = false;
};

}  // namespace pps

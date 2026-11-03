#include "party/party_server.hpp"

#include "common/crypto.hpp"
#include "common/json.hpp"
#include "party/session_stats.hpp"
#include "party/timeouts.hpp"
#include "party/watchdog.hpp"
#include "protocol/cost_planner.hpp"

#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>

namespace pps {
namespace {

constexpr std::size_t kMaxPending = 16384;
constexpr std::size_t kClosedSessionMemory = 256;

}  // namespace

PartyServer::PartyServer(PartyOptions options)
    : options_(std::move(options)),
      identity_(wire::party_identity(options_.party_id)),
      server_context_(credentials(), true),
      client_context_(credentials(), false),
      listener_(parse_endpoint(options_.listen).first, parse_endpoint(options_.listen).second,
                server_context_) {
    if (server_context_.identity() != identity_) {
        throw std::runtime_error("certificate identity '" + server_context_.identity() +
                                 "' does not match " + identity_);
    }
}

void PartyServer::run() {
    peer_ = PeerChannel::establish(options_.party_id, options_.peer, server_context_, client_context_);
    if (chdir(options_.runtime.c_str()) != 0) {
        throw std::runtime_error("cannot enter runtime directory " + options_.runtime);
    }
    // One MP-SPDZ virtual machine and TLS player per process, reused by
    // all sessions (MP-SPDZ keeps process-wide singletons).
    backend_ = std::make_unique<MpSpdzParty>(
        MpSpdzConfig{options_.party_id, options_.mpc_hosts, options_.mpc_port_base});
    log("MP-SPDZ semi2k channel to peer established");
    std::cout << JsonObject()
                     .add("event", "ready")
                     .add("party", options_.party_id)
                     .add("listen_port", listener_.port())
                     .str()
              << std::endl;
    for (std::uint64_t served = 0; options_.sessions == 0 || served < options_.sessions;
         ++served) {
        serve_session();
    }
    log("served requested number of sessions; exiting");
}

// ---- Logging and credentials -------------------------------------------------

TlsCredentials PartyServer::credentials() const {
    return pki_credentials(options_.pki, wire::party_identity(options_.party_id));
}

void PartyServer::log(const std::string& message) const {
    std::cerr << "[" << identity_ << "] " << message << std::endl;
}

void PartyServer::log_session(const Session& session, const std::string& message) const {
    log("session " + wire::session_hex(session.id) + ": " + message);
}

// ---- Connection intake --------------------------------------------------------

std::unique_ptr<TlsConnection> PartyServer::accept_one(Millis timeout) {
    try {
        return listener_.accept(timeout, kHandshakeTimeout);
    } catch (const TransportError& error) {
        log(std::string("rejected connection: ") + error.what());
        return nullptr;
    }
}

void PartyServer::park(std::unique_ptr<TlsConnection> connection) {
    if (pending_.size() >= kMaxPending) {
        pending_.front()->send_abort_noexcept({}, AbortCode::kInternal, "too many pending connections");
        pending_.pop_front();
    }
    pending_.push_back(std::move(connection));
}

std::unique_ptr<TlsConnection> PartyServer::take_pending_coordinator() {
    // pending_ only ever holds coordinator connections.
    if (pending_.empty()) {
        return nullptr;
    }
    auto connection = std::move(pending_.front());
    pending_.pop_front();
    return connection;
}

bool PartyServer::recently_closed(const wire::SessionId& session) const {
    return std::find(closed_sessions_.begin(), closed_sessions_.end(), session) !=
           closed_sessions_.end();
}

// An input owner connected while no session is collecting inputs: tell
// it to retry (session not open yet) or to stop (session already over).
void PartyServer::reject_outside_session(TlsConnection& connection) {
    try {
        const wire::Frame frame = connection.receive(Millis(2000));
        if (recently_closed(frame.session)) {
            connection.send_abort_noexcept(frame.session, AbortCode::kSessionClosed,
                                           "session already finished");
        } else {
            connection.send_abort_noexcept(frame.session, AbortCode::kUnknownSession,
                                           "session is not active");
        }
    } catch (const TransportError&) {
    }
}

// ---- Session phases -----------------------------------------------------------

void PartyServer::serve_session() {
    Session session;
    open_session(session);
    std::optional<AuthorizedSelection> selection;
    try {
        agree_on_session(session);
        collect_inputs(session);
        selection = compute(session);
    } catch (const SessionAbort& abort) {
        abort_session(session, abort.code, abort.what(), !abort.from_peer);
    } catch (const TransportError& error) {
        abort_session(session, AbortCode::kPeerFailure,
                      std::string("control channel failure: ") + error.what(), false);
        log("control channel to peer lost; exiting");
        std::exit(2);
    }
    if (selection) {
        deliver(session, *selection);
    }
    write_stats(session, selection);
    closed_sessions_.push_back(session.id);
    if (closed_sessions_.size() > kClosedSessionMemory) {
        closed_sessions_.pop_front();
    }
    if (fatal_backend_failure_) {
        log("MPC backend failed; exiting (fail-stop)");
        std::exit(3);
    }
}

void PartyServer::open_session(Session& session) {
    while (!session.coordinator) {
        auto connection = take_pending_coordinator();
        if (!connection) {
            connection = accept_one(Millis(1000));
        }
        if (!connection) {
            continue;
        }
        if (connection->peer_identity() != wire::kCoordinatorIdentity) {
            reject_outside_session(*connection);
            continue;
        }
        try {
            wire::Frame frame = connection->receive(kControlTimeout);
            if (frame.type != wire::MsgType::kSessionOpen) {
                throw ProtocolError("expected SessionOpen");
            }
            session.open = wire::decode_session_open(frame.payload);
            session.id = frame.session;
            session.open_payload = frame.payload;
        } catch (const TransportError& error) {
            log(std::string("invalid session request: ") + error.what());
            connection->send_abort_noexcept({}, error.code(), error.what());
            continue;
        }
        session.coordinator = std::move(connection);
    }
    session.started = Clock::now();
    const Millis timeout = std::min(Millis(session.open.timeout_ms), options_.max_input_timeout);
    session.input_deadline = session.started + timeout;
    for (const std::uint64_t id : session.open.station_ids) {
        session.stations.emplace(id, OwnerState{});
    }
    session.peer_traffic_start = peer_->counters();
    log_session(session, "opened: " + std::to_string(session.stations.size()) +
                             " stations, horizon " + std::to_string(session.open.horizon));
}

void PartyServer::agree_on_session(Session& session) {
    std::vector<std::uint8_t> transcript(session.id.begin(), session.id.end());
    transcript.insert(transcript.end(), session.open_payload.begin(),
                      session.open_payload.end());
    const auto digest = sha256(transcript);
    peer_->send(session.id, kSyncSessionOpen, 0, digest);
    const wire::PeerSync sync =
        peer_->expect(session.id, kSyncSessionOpen, remaining(session.input_deadline));
    if (sync.digest != digest) {
        throw SessionAbort(AbortCode::kPeerMismatch,
                           "parties received different session parameters");
    }
}

AuthorizedSelection PartyServer::compute(Session& session) {
    const std::size_t count = session.stations.size();
    if (count == 0) {
        return {};  // public: an empty station set has no match
    }
    // The search is oblivious, so its exact triple count is a function
    // of the public N alone and is generated before the online phase.
    const OperationCounts plan = plan_search(count);
    session.plan = plan;
    const std::uint64_t triples =
        plan.multiplications - std::min(options_.test_triple_shortfall, plan.multiplications);

    RequesterShares requester{session.requester.x, session.requester.y};
    std::vector<StationShares> stations;
    stations.reserve(count);
    for (const auto& [id, owner] : session.stations) {
        stations.push_back({id, owner.x, owner.y, owner.radius});
    }

    Watchdog watchdog(Clock::now() + options_.mpc_timeout, identity_);
    MpSpdzParty& backend = *backend_;
    try {
        backend.start_session();
        backend.generate_triples(triples);
        backend.begin_online();
        const AuthorizedSelection selection =
            nearest_eligible_station(backend, requester, stations, session.open.horizon);
        session.backend = backend.finish();
        if (session.backend->triples_remaining != 0 ||
            session.backend->triples_consumed != session.backend->triples_requested ||
            session.backend->operations.multiplications != plan.multiplications) {
            throw std::logic_error("triple plan mismatch");
        }
        return selection;
    } catch (const PreprocessingExhausted& error) {
        // Both parties exhaust at the same public point before any
        // exchange, so the backend stays consistent; end the session.
        session.backend = backend.finish();
        throw SessionAbort(AbortCode::kPreprocessingExhausted, error.what());
    } catch (const std::exception& error) {
        fatal_backend_failure_ = true;
        throw SessionAbort(AbortCode::kInternal, std::string("MPC failure: ") + error.what());
    }
}

void PartyServer::abort_session(Session& session, AbortCode code, const std::string& reason,
                   bool notify_peer) {
    log_session(session, std::string("aborted (") + abort_code_name(code) + "): " + reason);
    session.abort_status = std::string("aborted:") + abort_code_name(code);
    if (notify_peer && peer_) {
        try {
            peer_->send(session.id, kSyncAbort, static_cast<std::uint8_t>(code), {});
        } catch (const TransportError&) {
        }
    }
    if (session.coordinator) {
        session.coordinator->send_abort_noexcept(session.id, code, reason);
        session.coordinator->close();
    }
    if (session.requester.connection) {
        session.requester.connection->send_abort_noexcept(session.id, code, reason);
    }
    for (auto& [id, owner] : session.stations) {
        if (owner.connection) {
            owner.connection->send_abort_noexcept(session.id, code, "session aborted");
            owner.connection->close();
        }
    }
}

void PartyServer::write_stats(const Session& session,
                              const std::optional<AuthorizedSelection>& selection) {
    if (options_.stats_path.empty()) {
        return;
    }
    std::ofstream out(options_.stats_path, std::ios::app);
    out << session_stats_json(options_.party_id, session, selection,
                              peer_->counters() - session.peer_traffic_start)
        << '\n';
}

}  // namespace pps

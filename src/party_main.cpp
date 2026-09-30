// pp_party: one computation party (party ID 0 or 1) of the two-party search.
//
// Each process owns only its own TLS keys, its own local input shares, its own
// preprocessing material and its own MP-SPDZ channel state. See
// docs/ARCHITECTURE.md for the session protocol.

#include "pps/mpspdz_party.hpp"
#include "pps/search.hpp"
#include "pps/tls_transport.hpp"
#include "pps/util.hpp"
#include "pps/wire.hpp"

#include <unistd.h>

#include <chrono>
#include <climits>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <thread>

namespace {

using namespace pps;
using Clock = std::chrono::steady_clock;

constexpr Millis kHandshakeTimeout{5000};
constexpr Millis kControlTimeout{10000};
constexpr std::size_t kMaxPending = 16384;
constexpr std::size_t kClosedSessionMemory = 256;
constexpr std::uint32_t kSyncSessionOpen = 1;
constexpr std::uint32_t kSyncInputsComplete = 2;
constexpr std::uint32_t kSyncAbort = 3;

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

class SessionAbort : public std::runtime_error {
public:
    SessionAbort(AbortCode code, const std::string& message, bool from_peer = false)
        : std::runtime_error(message), code(code), from_peer(from_peer) {}
    AbortCode code;
    bool from_peer;
};

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
    std::optional<BackendStats> backend;
    std::optional<OperationCounts> plan;
};

std::string counters_json(const TransportCounters& counters) {
    return JsonObject()
        .add("bytes_sent", counters.bytes_sent)
        .add("bytes_received", counters.bytes_received)
        .add("messages_sent", counters.messages_sent)
        .add("messages_received", counters.messages_received)
        .str();
}

TransportCounters difference(const TransportCounters& after, const TransportCounters& before) {
    return {after.bytes_sent - before.bytes_sent, after.bytes_received - before.bytes_received,
            after.messages_sent - before.messages_sent,
            after.messages_received - before.messages_received};
}

double seconds_between(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double>(end - start).count();
}

Millis remaining(Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<Millis>(deadline - Clock::now());
    return left.count() > 0 ? left : Millis(0);
}

// Terminates the process if the MPC phase outlives its bound; MP-SPDZ state
// after a stalled peer cannot be resumed safely (fail-stop, no output).
class Watchdog {
public:
    Watchdog(Clock::time_point deadline, std::string label) {
        thread_ = std::thread([this, deadline, label] {
            std::unique_lock<std::mutex> lock(mutex_);
            if (!condition_.wait_until(lock, deadline, [this] { return done_; })) {
                std::fprintf(stderr, "%s: MPC watchdog expired; terminating without output\n",
                             label.c_str());
                std::fflush(stderr);
                std::_Exit(4);
            }
        });
    }
    ~Watchdog() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            done_ = true;
        }
        condition_.notify_all();
        thread_.join();
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread thread_;
};

class PartyServer {
public:
    explicit PartyServer(PartyOptions options)
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

    void run() {
        connect_peer();
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

private:
    TlsCredentials credentials() const {
        const PkiFiles files = pki_files(options_.pki, wire::party_identity(options_.party_id));
        return {files.ca, files.certificate, files.key};
    }

    void log(const std::string& message) const {
        std::cerr << "[" << identity_ << "] " << message << std::endl;
    }

    void log_session(const Session& session, const std::string& message) const {
        log("session " + wire::session_hex(session.id) + ": " + message);
    }

    // ---- Party-to-party control channel -----------------------------------

    void connect_peer() {
        const auto [host, port] = parse_endpoint(options_.peer);
        const auto deadline = Clock::now() + Millis(120000);
        const std::string expected = wire::party_identity(1 - options_.party_id);
        if (options_.party_id == 0) {
            TlsListener peer_listener(host, port, server_context_);
            while (!peer_) {
                if (Clock::now() >= deadline) {
                    throw std::runtime_error("party1 did not connect to the control channel");
                }
                try {
                    auto connection = peer_listener.accept(remaining(deadline), kHandshakeTimeout);
                    if (connection && connection->peer_identity() == expected) {
                        peer_ = std::move(connection);
                    } else if (connection) {
                        log("rejected control connection from " + connection->peer_identity());
                    }
                } catch (const TransportError& error) {
                    log(std::string("control-channel handshake failed: ") + error.what());
                }
            }
        } else {
            while (!peer_) {
                try {
                    peer_ = tls_connect(host, port, client_context_, expected, kHandshakeTimeout);
                } catch (const TransportError& error) {
                    if (Clock::now() >= deadline) {
                        throw;
                    }
                    std::this_thread::sleep_for(Millis(200));
                }
            }
        }
        log("control channel to " + expected + " established");
    }

    void send_peer_sync(const Session& session, std::uint32_t phase, std::uint8_t status,
                        const std::array<std::uint8_t, 32>& digest) {
        wire::PeerSync sync;
        sync.phase = phase;
        sync.status = status;
        sync.digest = digest;
        peer_->send(wire::make_frame(wire::MsgType::kPeerSync, session.id, sync), kControlTimeout);
    }

    // Returns the next control message for this session; skips stale frames
    // of earlier sessions. Peer aborts become SessionAbort.
    std::optional<wire::PeerSync> read_peer_sync(const Session& session, Millis timeout) {
        const auto deadline = Clock::now() + timeout;
        while (true) {
            wire::Frame frame = peer_->receive(remaining(deadline));
            if (frame.type != wire::MsgType::kPeerSync) {
                throw std::runtime_error("unexpected message on control channel");
            }
            const wire::PeerSync sync = wire::decode_peer_sync(frame.payload);
            if (frame.session != session.id) {
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

    wire::PeerSync expect_peer_sync(const Session& session, std::uint32_t phase, Millis timeout) {
        try {
            const auto sync = read_peer_sync(session, timeout);
            if (sync->phase != phase) {
                throw SessionAbort(AbortCode::kPeerMismatch, "peer party is in another phase");
            }
            return *sync;
        } catch (const TimeoutError&) {
            throw SessionAbort(AbortCode::kTimeout, "peer party did not respond in time");
        }
    }

    // ---- Connection intake ---------------------------------------------------

    std::unique_ptr<TlsConnection> accept_one(Millis timeout) {
        try {
            return listener_.accept(timeout, kHandshakeTimeout);
        } catch (const TransportError& error) {
            log(std::string("rejected connection: ") + error.what());
            return nullptr;
        }
    }

    void park(std::unique_ptr<TlsConnection> connection) {
        if (pending_.size() >= kMaxPending) {
            pending_.front()->send_abort_noexcept({}, AbortCode::kInternal, "too many pending connections");
            pending_.pop_front();
        }
        pending_.push_back(std::move(connection));
    }

    std::unique_ptr<TlsConnection> take_pending(bool coordinator) {
        for (auto it = pending_.begin(); it != pending_.end(); ++it) {
            if (((*it)->peer_identity() == wire::kCoordinatorIdentity) == coordinator) {
                auto connection = std::move(*it);
                pending_.erase(it);
                return connection;
            }
        }
        return nullptr;
    }

    bool recently_closed(const wire::SessionId& session) const {
        return std::find(closed_sessions_.begin(), closed_sessions_.end(), session) !=
               closed_sessions_.end();
    }

    // An input owner connected while no session is collecting inputs: tell
    // it to retry (session not open yet) or to stop (session already over).
    void reject_outside_session(TlsConnection& connection) {
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

    // ---- Session -------------------------------------------------------------

    void serve_session() {
        Session session;
        if (!open_session(session)) {
            return;
        }
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

    bool open_session(Session& session) {
        while (!session.coordinator) {
            auto connection = take_pending(true);
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
        return true;
    }

    void agree_on_session(Session& session) {
        std::vector<std::uint8_t> transcript(session.id.begin(), session.id.end());
        transcript.insert(transcript.end(), session.open_payload.begin(),
                          session.open_payload.end());
        const auto digest = sha256(transcript);
        send_peer_sync(session, kSyncSessionOpen, 0, digest);
        const wire::PeerSync sync =
            expect_peer_sync(session, kSyncSessionOpen, remaining(session.input_deadline));
        if (sync.digest != digest) {
            throw SessionAbort(AbortCode::kPeerMismatch,
                               "parties received different session parameters");
        }
    }

    void poll_peer(Session& session) {
        while (peer_->wait_readable(Millis(0))) {
            const auto sync = read_peer_sync(session, kControlTimeout);
            if (sync->phase != kSyncInputsComplete || session.peer_inputs) {
                throw SessionAbort(AbortCode::kPeerMismatch, "unexpected control message");
            }
            session.peer_inputs = *sync;
        }
    }

    void collect_inputs(Session& session) {
        std::size_t outstanding = 1 + session.stations.size();
        while (outstanding > 0) {
            if (Clock::now() >= session.input_deadline) {
                throw SessionAbort(AbortCode::kTimeout,
                                   std::to_string(outstanding) + " input owner(s) missing at deadline");
            }
            poll_peer(session);
            auto connection = accept_one(std::min(Millis(100), remaining(session.input_deadline)));
            if (!connection) {
                continue;
            }
            if (connection->peer_identity() == wire::kCoordinatorIdentity) {
                park(std::move(connection));
                continue;
            }
            if (receive_owner_inputs(session, std::move(connection))) {
                --outstanding;
            }
        }
        session.input_seconds = seconds_between(session.started, Clock::now());

        // Both parties must hold shares of the same submissions.
        std::vector<std::uint8_t> transcript(session.id.begin(), session.id.end());
        transcript.insert(transcript.end(), session.requester.submission_id.begin(),
                          session.requester.submission_id.end());
        for (const auto& [id, owner] : session.stations) {
            for (int i = 0; i < 8; ++i) {
                transcript.push_back(static_cast<std::uint8_t>(id >> (8 * i)));
            }
            transcript.insert(transcript.end(), owner.submission_id.begin(),
                              owner.submission_id.end());
        }
        const auto digest = sha256(transcript);
        send_peer_sync(session, kSyncInputsComplete, 0, digest);
        const wire::PeerSync sync = session.peer_inputs
                                        ? *session.peer_inputs
                                        : expect_peer_sync(session, kSyncInputsComplete,
                                                           remaining(session.input_deadline) + kControlTimeout);
        if (sync.digest != digest) {
            throw SessionAbort(AbortCode::kPeerMismatch, "parties hold different input sets");
        }
    }

    // Returns true when an expected owner completed its submission. Rejects
    // unknown identities, duplicate submissions and other sessions without
    // aborting; malformed or incomplete submissions abort the session.
    bool receive_owner_inputs(Session& session, std::unique_ptr<TlsConnection> connection) {
        const std::string who = connection->peer_identity();
        OwnerState* owner = nullptr;
        wire::OwnerKind kind = wire::OwnerKind::kRequester;
        std::uint64_t station_id = 0;
        if (who == wire::requester_identity(session.open.requester)) {
            owner = &session.requester;
        } else if (who.rfind("station:", 0) == 0) {
            try {
                station_id = parse_u64(who.substr(8));
                const auto it = session.stations.find(station_id);
                if (it != session.stations.end()) {
                    owner = &it->second;
                    kind = wire::OwnerKind::kStation;
                }
            } catch (const std::exception&) {
            }
        }
        if (owner == nullptr) {
            connection->send_abort_noexcept(session.id, AbortCode::kUnauthorized,
                                            "identity is not an input owner of this session");
            log_session(session, "rejected unexpected identity " + who);
            return false;
        }
        if (owner->done || owner->connection) {
            connection->send_abort_noexcept(session.id, AbortCode::kDuplicate,
                                            "duplicate submission for this input owner");
            log_session(session, "rejected duplicate submission from " + who);
            return false;
        }

        const auto owner_deadline =
            std::min(session.input_deadline, Clock::now() + options_.owner_timeout);
        wire::Frame frame;
        try {
            frame = connection->receive(remaining(owner_deadline));
        } catch (const TransportError& error) {
            session.input_traffic += connection->counters();
            throw SessionAbort(error.code(), who + ": " + error.what());
        }
        if (frame.session != session.id) {
            // Submission for another session: retry later, or stop if over.
            connection->send_abort_noexcept(
                frame.session,
                recently_closed(frame.session) ? AbortCode::kSessionClosed : AbortCode::kUnknownSession,
                "session is not active");
            return false;
        }

        const std::uint8_t expected_fields = kind == wire::OwnerKind::kStation ? 0b111 : 0b011;
        try {
            while (true) {
                if (frame.session != session.id) {
                    throw ProtocolError(AbortCode::kUnknownSession, "session changed mid-submission");
                }
                if (frame.type == wire::MsgType::kInputShare) {
                    const wire::InputShare share = wire::decode_input_share(frame.payload);
                    if (share.owner != kind || share.station_id != station_id) {
                        throw ProtocolError(AbortCode::kUnauthorized,
                                            "input share does not match authenticated owner");
                    }
                    const auto bit = static_cast<std::uint8_t>(1u << (static_cast<int>(share.field) - 1));
                    if ((expected_fields & bit) == 0) {
                        throw ProtocolError("field not valid for this owner");
                    }
                    if ((owner->fields & bit) != 0) {
                        throw ProtocolError(AbortCode::kDuplicate, "duplicate input field");
                    }
                    owner->fields |= bit;
                    LocalShare& target = share.field == wire::Field::kX   ? owner->x
                                         : share.field == wire::Field::kY ? owner->y
                                                                          : owner->radius;
                    target.value = share.share;
                } else if (frame.type == wire::MsgType::kInputDone) {
                    const wire::InputDone done = wire::decode_input_done(frame.payload);
                    if (done.owner != kind || done.station_id != station_id ||
                        done.field_count != static_cast<std::uint32_t>(std::popcount(expected_fields)) ||
                        owner->fields != expected_fields) {
                        throw ProtocolError("incomplete or inconsistent input submission");
                    }
                    owner->submission_id = done.submission_id;
                    connection->send(wire::make_frame(wire::MsgType::kInputAck, session.id, done),
                                     kControlTimeout);
                    break;
                } else {
                    throw ProtocolError("unexpected message during input phase");
                }
                frame = connection->receive(remaining(owner_deadline));
            }
        } catch (const TransportError& error) {
            connection->send_abort_noexcept(session.id, error.code(), error.what());
            session.input_traffic += connection->counters();
            throw SessionAbort(error.code(), who + ": " + error.what());
        }

        session.input_traffic += connection->counters();
        owner->done = true;
        if (kind == wire::OwnerKind::kStation) {
            owner->connection = std::move(connection);  // kept for output delivery
        }
        return true;
    }

    AuthorizedSelection compute(Session& session) {
        const std::size_t count = session.stations.size();
        if (count == 0) {
            return {};  // public: an empty station set has no match
        }
        // The search is oblivious, so its exact triple count is a function
        // of the public (N, D) alone and is generated before the online phase.
        const OperationCounts plan = plan_search(count, session.open.horizon);
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

    void deliver(Session& session, const AuthorizedSelection& selection) {
        const auto start = Clock::now();
        for (auto& [id, owner] : session.stations) {
            if (!owner.connection) {
                continue;
            }
            try {
                if (selection.match && id == selection.station_id) {
                    for (const auto& [field, share] :
                         {std::pair{wire::Field::kX, session.requester.x},
                          std::pair{wire::Field::kY, session.requester.y}}) {
                        owner.connection->send(
                            wire::make_frame(wire::MsgType::kOutputShare, session.id,
                                             wire::OutputShare{id, field, share.value}),
                            kControlTimeout);
                    }
                    session.output_delivered = true;
                } else {
                    owner.connection->send(wire::make_frame(wire::MsgType::kNoOutput, session.id,
                                                            wire::NoOutput{id}),
                                           kControlTimeout);
                }
            } catch (const TransportError& error) {
                log_session(session, "output delivery to station " + std::to_string(id) +
                                         " failed: " + error.what());
            }
            const TransportCounters counters = owner.connection->counters();
            session.output_traffic.bytes_sent += counters.bytes_sent;
            session.output_traffic.messages_sent += counters.messages_sent;
            owner.connection->close();
            owner.connection.reset();
        }
        try {
            const TransportCounters before = session.coordinator->counters();
            session.coordinator->send(
                wire::make_frame(wire::MsgType::kSessionResult, session.id,
                                 wire::SessionResult{selection.match,
                                                     selection.match ? selection.station_id : 0}),
                kControlTimeout);
            session.output_traffic += difference(session.coordinator->counters(), before);
        } catch (const TransportError& error) {
            log_session(session, std::string("result delivery to coordinator failed: ") + error.what());
        }
        session.output_seconds = seconds_between(start, Clock::now());
        log_session(session, selection.match ? "completed with a match" : "completed without a match");
    }

    void abort_session(Session& session, AbortCode code, const std::string& reason,
                       bool notify_peer) {
        log_session(session, std::string("aborted (") + abort_code_name(code) + "): " + reason);
        session_status_ = std::string("aborted:") + abort_code_name(code);
        if (notify_peer && peer_) {
            try {
                send_peer_sync(session, kSyncAbort, static_cast<std::uint8_t>(code), {});
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

    void write_stats(const Session& session, const std::optional<AuthorizedSelection>& selection) {
        const std::string status = selection ? "ok" : session_status_;
        session_status_.clear();
        if (options_.stats_path.empty()) {
            return;
        }
        JsonObject json;
        json.add("party", options_.party_id)
            .add("session", wire::session_hex(session.id))
            .add("status", status)
            .add("stations", static_cast<std::uint64_t>(session.stations.size()))
            .add("horizon", std::uint64_t{session.open.horizon})
            .add("input_phase_s", session.input_seconds)
            .add("output_phase_s", session.output_seconds)
            .add("output_delivered", session.output_delivered);
        if (selection) {
            json.add("match", selection->match);
            if (selection->match) {
                json.add("selected_station", selection->station_id);
            }
        }
        const auto counts_json = [](const OperationCounts& ops) {
            return JsonObject()
                .add("multiplications", ops.multiplications)
                .add("comparisons", ops.comparisons)
                .add("halvings", ops.halvings)
                .add("multiply_steps", ops.multiply_steps)
                .add("compare_steps", ops.compare_steps)
                .add("halve_steps", ops.halve_steps)
                .add("reveal_steps", ops.reveal_steps)
                .str();
        };
        if (session.plan) {
            json.add_raw("plan", counts_json(*session.plan));
        }
        if (session.backend) {
            const BackendStats& backend = *session.backend;
            json.add_raw("operations", counts_json(backend.operations));
            const auto phase = [](const PhaseCost& cost) {
                return JsonObject()
                    .add("seconds", cost.seconds)
                    .add("bytes_sent", cost.bytes_sent)
                    .add("rounds", cost.rounds)
                    .str();
            };
            json.add_raw("mpc_connect", phase(backend.connect))
                .add_raw("offline", phase(backend.offline))
                .add_raw("online", phase(backend.online))
                .add("triples_requested", backend.triples_requested)
                .add("triples_consumed", backend.triples_consumed)
                .add("triples_remaining", backend.triples_remaining);
        }
        json.add_raw("transport",
                     JsonObject()
                         .add_raw("inputs", counters_json(session.input_traffic))
                         .add_raw("outputs", counters_json(session.output_traffic))
                         .add_raw("peer_control",
                                  counters_json(difference(peer_->counters(), session.peer_traffic_start)))
                         .str());
        std::ofstream out(options_.stats_path, std::ios::app);
        out << json.str() << '\n';
    }

    PartyOptions options_;
    std::string identity_;
    TlsContext server_context_;
    TlsContext client_context_;
    TlsListener listener_;
    std::unique_ptr<TlsConnection> peer_;
    std::unique_ptr<MpSpdzParty> backend_;
    std::deque<std::unique_ptr<TlsConnection>> pending_;  // coordinators only
    std::deque<wire::SessionId> closed_sessions_;
    bool fatal_backend_failure_ = false;
    std::string session_status_;
};

std::string absolute(const std::string& path) {
    char resolved[PATH_MAX];
    if (realpath(path.c_str(), resolved) == nullptr) {
        throw std::runtime_error("path does not exist: " + path);
    }
    return resolved;
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        const std::size_t end = text.find(separator, start);
        parts.push_back(text.substr(start, end - start));
        if (end == std::string::npos) {
            return parts;
        }
        start = end + 1;
    }
}

void usage() {
    std::cerr
        << "Usage: pp_party --party-id <0|1> --listen <host:port> --peer <host:port>\n"
           "                --mpc-hosts <host0,host1> --mpc-port-base <port>\n"
           "                --pki <dir> --runtime <dir>\n"
           "                [--sessions <n>] [--max-input-timeout-ms <ms>]\n"
           "                [--mpc-timeout-ms <ms>] [--owner-timeout-ms <ms>]\n"
           "                [--stats <file>]\n"
           "                [--test-triple-shortfall <n>]   (fault injection, tests only)\n"
           "  party 0 listens on --peer for party 1's control connection;\n"
           "  party 1 connects to party 0 at --peer.\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    pps::raise_file_descriptor_limit();
    try {
        const pps::Arguments arguments(argc, argv, 1);
        arguments.allow_only({"party-id", "listen", "peer", "mpc-hosts", "mpc-port-base", "pki",
                              "runtime", "sessions", "max-input-timeout-ms", "mpc-timeout-ms",
                              "stats", "owner-timeout-ms", "test-triple-shortfall"});
        PartyOptions options;
        options.party_id = static_cast<int>(arguments.get_uint("party-id"));
        if (options.party_id > 1) {
            throw std::invalid_argument("--party-id must be 0 or 1");
        }
        options.listen = arguments.get("listen");
        options.peer = arguments.get("peer");
        options.mpc_hosts = split(arguments.get("mpc-hosts"), ',');
        if (options.mpc_hosts.size() != 2) {
            throw std::invalid_argument("--mpc-hosts needs exactly two hosts");
        }
        options.mpc_port_base = static_cast<int>(arguments.get_uint("mpc-port-base"));
        options.pki = absolute(arguments.get("pki"));
        options.runtime = absolute(arguments.get("runtime"));
        options.sessions = arguments.get_uint("sessions", 0);
        options.max_input_timeout = Millis(arguments.get_uint("max-input-timeout-ms", 120000));
        options.mpc_timeout = Millis(arguments.get_uint("mpc-timeout-ms", 600000));
        options.owner_timeout = Millis(arguments.get_uint("owner-timeout-ms", 10000));
        if (arguments.has("stats")) {
            const std::string stats = arguments.get("stats");
            options.stats_path = stats.front() == '/' ? stats : absolute(".") + "/" + stats;
        }
        options.test_triple_shortfall = arguments.get_uint("test-triple-shortfall", 0);
        PartyServer(options).run();
        return 0;
    } catch (const std::invalid_argument& error) {
        std::cerr << "error: " << error.what() << "\n";
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "fatal: " << error.what() << "\n";
        return 1;
    }
}

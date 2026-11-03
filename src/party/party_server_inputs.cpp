// Input phase: receives one additive share per field from every input owner
// over its authenticated connection, then checks with the peer party that both
// hold shares of the same submissions.

#include "common/arguments.hpp"
#include "common/crypto.hpp"
#include "party/party_server.hpp"
#include "party/timeouts.hpp"

#include <algorithm>
#include <bit>

namespace pps {
namespace {

// The input owner an authenticated identity maps to in this session.
struct OwnerRef {
    OwnerState* state = nullptr;  // nullptr: not an input owner of this session
    wire::OwnerKind kind = wire::OwnerKind::kRequester;
    std::uint64_t station_id = 0;
};

OwnerRef find_owner(Session& session, const std::string& who) {
    OwnerRef owner;
    if (who == wire::requester_identity(session.open.requester)) {
        owner.state = &session.requester;
    } else if (who.rfind("station:", 0) == 0) {
        try {
            owner.station_id = parse_u64(who.substr(8));
            const auto it = session.stations.find(owner.station_id);
            if (it != session.stations.end()) {
                owner.state = &it->second;
                owner.kind = wire::OwnerKind::kStation;
            }
        } catch (const std::exception&) {
        }
    }
    return owner;
}

void store_share(const wire::Frame& frame, const OwnerRef& owner, std::uint8_t expected_fields) {
    const wire::InputShare share = wire::decode_input_share(frame.payload);
    if (share.owner != owner.kind || share.station_id != owner.station_id) {
        throw ProtocolError(AbortCode::kUnauthorized,
                            "input share does not match authenticated owner");
    }
    const auto bit = static_cast<std::uint8_t>(1u << (static_cast<int>(share.field) - 1));
    if ((expected_fields & bit) == 0) {
        throw ProtocolError("field not valid for this owner");
    }
    if ((owner.state->fields & bit) != 0) {
        throw ProtocolError(AbortCode::kDuplicate, "duplicate input field");
    }
    owner.state->fields |= bit;
    LocalShare& target = share.field == wire::Field::kX   ? owner.state->x
                         : share.field == wire::Field::kY ? owner.state->y
                                                          : owner.state->radius;
    target.value = share.share;
}

// Reads frames, starting with `frame`, until the owner's InputDone is accepted
// and acknowledged. Any violation throws.
void read_submission(TlsConnection& connection, const wire::SessionId& session, const OwnerRef& owner,
                     wire::Frame frame, Clock::time_point deadline) {
    const std::uint8_t expected_fields = owner.kind == wire::OwnerKind::kStation ? 0b111 : 0b011;
    while (true) {
        if (frame.session != session) {
            throw ProtocolError(AbortCode::kUnknownSession, "session changed mid-submission");
        }
        if (frame.type == wire::MsgType::kInputShare) {
            store_share(frame, owner, expected_fields);
        } else if (frame.type == wire::MsgType::kInputDone) {
            const wire::InputDone done = wire::decode_input_done(frame.payload);
            if (done.owner != owner.kind || done.station_id != owner.station_id ||
                done.field_count != static_cast<std::uint32_t>(std::popcount(expected_fields)) ||
                owner.state->fields != expected_fields) {
                throw ProtocolError("incomplete or inconsistent input submission");
            }
            owner.state->submission_id = done.submission_id;
            connection.send(wire::make_frame(wire::MsgType::kInputAck, session, done), kControlTimeout);
            return;
        } else {
            throw ProtocolError("unexpected message during input phase");
        }
        frame = connection.receive(remaining(deadline));
    }
}

// Digest both parties compare: session ID and every owner's submission ID.
std::array<std::uint8_t, 32> input_set_digest(const Session& session) {
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
    return sha256(transcript);
}

}  // namespace

void PartyServer::poll_peer(Session& session) {
    while (peer_->has_pending_message()) {
        const wire::PeerSync sync = peer_->read(session.id, kControlTimeout);
        if (sync.phase != kSyncInputsComplete || session.peer_inputs) {
            throw SessionAbort(AbortCode::kPeerMismatch, "unexpected control message");
        }
        session.peer_inputs = sync;
    }
}

void PartyServer::collect_inputs(Session& session) {
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
    const auto digest = input_set_digest(session);
    peer_->send(session.id, kSyncInputsComplete, 0, digest);
    const wire::PeerSync sync = session.peer_inputs
                                    ? *session.peer_inputs
                                    : peer_->expect(session.id, kSyncInputsComplete,
                                                    remaining(session.input_deadline) + kControlTimeout);
    if (sync.digest != digest) {
        throw SessionAbort(AbortCode::kPeerMismatch, "parties hold different input sets");
    }
}

// Returns true when an expected owner completed its submission. Rejects
// unknown identities, duplicate submissions and other sessions without
// aborting; malformed or incomplete submissions abort the session.
bool PartyServer::receive_owner_inputs(Session& session, std::unique_ptr<TlsConnection> connection) {
    const std::string who = connection->peer_identity();
    const OwnerRef owner = find_owner(session, who);
    if (owner.state == nullptr) {
        connection->send_abort_noexcept(session.id, AbortCode::kUnauthorized,
                                        "identity is not an input owner of this session");
        log_session(session, "rejected unexpected identity " + who);
        return false;
    }
    if (owner.state->done || owner.state->connection) {
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

    try {
        read_submission(*connection, session.id, owner, std::move(frame), owner_deadline);
    } catch (const TransportError& error) {
        connection->send_abort_noexcept(session.id, error.code(), error.what());
        session.input_traffic += connection->counters();
        throw SessionAbort(error.code(), who + ": " + error.what());
    }

    session.input_traffic += connection->counters();
    owner.state->done = true;
    if (owner.kind == wire::OwnerKind::kStation) {
        owner.state->connection = std::move(connection);  // kept for output delivery
    }
    return true;
}

}  // namespace pps

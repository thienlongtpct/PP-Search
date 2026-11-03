// Output phase: sends this party's coordinate shares only to the selected
// station, a no-output notice to the others, and the public result to the
// coordinator.

#include "party/party_server.hpp"
#include "party/timeouts.hpp"

#include <utility>

namespace pps {

void PartyServer::deliver(Session& session, const AuthorizedSelection& selection) {
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
        session.output_traffic += session.coordinator->counters() - before;
    } catch (const TransportError& error) {
        log_session(session, std::string("result delivery to coordinator failed: ") + error.what());
    }
    session.output_seconds = seconds_between(start, Clock::now());
    log_session(session, selection.match ? "completed with a match" : "completed without a match");
}

}  // namespace pps

#include "party/session_stats.hpp"

#include "common/json.hpp"

namespace pps {
namespace {

std::string counters_json(const TransportCounters& counters) {
    return JsonObject()
        .add("bytes_sent", counters.bytes_sent)
        .add("bytes_received", counters.bytes_received)
        .add("messages_sent", counters.messages_sent)
        .add("messages_received", counters.messages_received)
        .str();
}

std::string counts_json(const OperationCounts& ops) {
    return JsonObject()
        .add("multiplications", ops.multiplications)
        .add("comparisons", ops.comparisons)
        .add("range_checks", ops.range_checks)
        .add("multiply_steps", ops.multiply_steps)
        .add("compare_steps", ops.compare_steps)
        .add("range_check_steps", ops.range_check_steps)
        .add("reveal_steps", ops.reveal_steps)
        .str();
}

std::string phase_json(const PhaseCost& cost) {
    return JsonObject()
        .add("seconds", cost.seconds)
        .add("bytes_sent", cost.bytes_sent)
        .add("rounds", cost.rounds)
        .str();
}

}  // namespace

std::string session_stats_json(int party_id, const Session& session,
                               const std::optional<AuthorizedSelection>& selection,
                               const TransportCounters& peer_control) {
    JsonObject json;
    json.add("party", party_id)
        .add("session", wire::session_hex(session.id))
        .add("status", selection ? "ok" : session.abort_status)
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
    if (session.plan) {
        json.add_raw("plan", counts_json(*session.plan));
    }
    if (session.backend) {
        const BackendStats& backend = *session.backend;
        json.add_raw("operations", counts_json(backend.operations))
            .add_raw("mpc_connect", phase_json(backend.connect))
            .add_raw("offline", phase_json(backend.offline))
            .add_raw("online", phase_json(backend.online))
            .add("triples_requested", backend.triples_requested)
            .add("triples_consumed", backend.triples_consumed)
            .add("triples_remaining", backend.triples_remaining);
    }
    json.add_raw("transport",
                 JsonObject()
                     .add_raw("inputs", counters_json(session.input_traffic))
                     .add_raw("outputs", counters_json(session.output_traffic))
                     .add_raw("peer_control", counters_json(peer_control))
                     .str());
    return json.str();
}

}  // namespace pps

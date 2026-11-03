#pragma once

#include "party/session.hpp"

#include <optional>
#include <string>

namespace pps {

// One-line JSON record of a finished session, written to --stats. It contains
// only public values: counts, sizes, timings and the authorised output.
std::string session_stats_json(int party_id, const Session& session,
                               const std::optional<AuthorizedSelection>& selection,
                               const TransportCounters& peer_control);

}  // namespace pps

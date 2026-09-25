#pragma once

// Plaintext reference functionality. Used only by tests and benchmark
// correctness checks; it is never linked into a computation party.

#include "pps/ring.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace pps {

struct PlainStation {
    std::uint64_t id;
    std::int32_t x;
    std::int32_t y;
    std::uint32_t support_radius;
};

struct PlainSelection {
    bool match = false;
    std::uint64_t station_id = 0;
    bool operator==(const PlainSelection&) const = default;
};

inline Word plain_squared_distance(std::int32_t ax, std::int32_t ay,
                                   std::int32_t bx, std::int32_t by) {
    const SignedWord dx = SignedWord{ax} - bx;
    const SignedWord dy = SignedWord{ay} - by;
    return static_cast<Word>(dx * dx + dy * dy);
}

// Eligible station minimising (q, station_id); inclusive radius and horizon.
inline PlainSelection plain_nearest_eligible(std::int32_t ax, std::int32_t ay,
                                             std::span<const PlainStation> stations,
                                             std::uint32_t horizon) {
    std::optional<Word> best_q;
    PlainSelection best;
    const Word horizon_squared = Word{horizon} * horizon;
    for (const PlainStation& station : stations) {
        const Word q = plain_squared_distance(ax, ay, station.x, station.y);
        const Word radius_squared = Word{station.support_radius} * station.support_radius;
        if (q > radius_squared || q > horizon_squared) {
            continue;
        }
        if (!best_q || q < *best_q || (q == *best_q && station.id < best.station_id)) {
            best_q = q;
            best = {true, station.id};
        }
    }
    return best;
}

}  // namespace pps

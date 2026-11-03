#pragma once

// Monotonic-clock helpers for the timeouts used across the session protocol.

#include <chrono>

namespace pps {

using Clock = std::chrono::steady_clock;
using Millis = std::chrono::milliseconds;

// Time left until `deadline`, never negative.
inline Millis remaining(Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<Millis>(deadline - Clock::now());
    return left.count() > 0 ? left : Millis(0);
}

inline double seconds_between(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double>(end - start).count();
}

}  // namespace pps

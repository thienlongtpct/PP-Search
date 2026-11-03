#pragma once

// Nearest eligible station search over secret-shared inputs.
//
//   q_i        = (A_x - P_ix)^2 + (A_y - P_iy)^2          (computed once)
//   in_domain_i = the requester's and station i's inputs are in their domains
//   eligible_i  = in_domain_i AND [q_i <= R_i^2] AND [q_i <= D^2]
//   result      = eligible station minimising (q_i, station_id), or no match
//
// Fully oblivious: control flow, round count and every operation's size
// depend only on the public station count N, never on secret data. The horizon
// D is only an eligibility constraint and does not change the schedule. No
// intermediate value is opened; the only reconstruction is the final
// (match bit, match * selected ID) pair the output policy authorises.
//
// The eligibility bits directly become the tournament's validity bits, so an
// exact tournament over all N stations selects the minimum (q, id) among the
// eligible stations. Every station takes part; invalid leaves stay in the
// schedule.
//
// Input domains: an input owner chooses its shares, and the parties cannot see
// the value they add up to. Comparisons only read low ring bits, so an input
// outside its domain could otherwise wrap a distance into looking small, win the
// selection and receive the requester's coordinates. A station with such an
// input is never eligible, and such a requester input gives no match. Any
// distance computed from these inputs is harmless: comparisons still return
// bits, and the tournament ignores the distance of an invalid candidate.
//
// Tie-breaking without comparing IDs: stations are processed in ascending
// public ID order, and the tournament always pairs adjacent contiguous
// ranges, so every station in a left subtree has a smaller ID than every
// station in the right subtree. Taking the right candidate only when its q is
// strictly smaller therefore yields the lexicographic minimum of (q, id),
// independent of the order in which inputs arrived.

#include "protocol/secure_ops.hpp"

#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace pps {

struct RequesterShares {
    LocalShare x;
    LocalShare y;
};

struct StationShares {
    std::uint64_t id = 0;  // public
    LocalShare x;
    LocalShare y;
    LocalShare radius;
};

namespace detail {

struct Candidates {
    std::vector<LocalShare> valid;
    std::vector<LocalShare> distance;
    std::vector<LocalShare> id;
};

// One tournament level: combines adjacent pairs and carries an unpaired last
// entry forward unchanged.
inline Candidates tournament_round(SecureOps& ops, const Candidates& layer) {
    const std::size_t pairs = layer.valid.size() / 2;
    std::vector<LocalShare> left_q(pairs), right_q(pairs), left_valid(pairs),
        right_valid(pairs), left_id(pairs), right_id(pairs);
    for (std::size_t i = 0; i < pairs; ++i) {
        left_q[i] = layer.distance[2 * i];
        right_q[i] = layer.distance[2 * i + 1];
        left_valid[i] = layer.valid[2 * i];
        right_valid[i] = layer.valid[2 * i + 1];
        left_id[i] = layer.id[2 * i];
        right_id[i] = layer.id[2 * i + 1];
    }

    // right_better = [right.q < left.q] = NOT [left.q <= right.q]
    const std::vector<LocalShare> left_not_worse = ops.less_equal(left_q, right_q);

    // One round: t1 = (1 - vL) * right_better, t2 = vL * vR.
    std::vector<LocalShare> factors_a(2 * pairs), factors_b(2 * pairs);
    for (std::size_t i = 0; i < pairs; ++i) {
        factors_a[i] = ops.not_bit(left_valid[i]);
        factors_b[i] = ops.not_bit(left_not_worse[i]);
        factors_a[pairs + i] = left_valid[i];
        factors_b[pairs + i] = right_valid[i];
    }
    const std::vector<LocalShare> products = ops.multiply(factors_a, factors_b);

    std::vector<LocalShare> prefer_right(pairs), valid(pairs);
    for (std::size_t i = 0; i < pairs; ++i) {
        // (NOT vL) OR right_better
        prefer_right[i] = SecureOps::sub(SecureOps::add(factors_a[i], factors_b[i]), products[i]);
        // vL OR vR
        valid[i] = SecureOps::sub(SecureOps::add(left_valid[i], right_valid[i]),
                                  products[pairs + i]);
    }
    const std::vector<LocalShare> take_right = ops.and_bits(right_valid, prefer_right);

    std::vector<LocalShare> condition(2 * pairs), when_true(2 * pairs), when_false(2 * pairs);
    for (std::size_t i = 0; i < pairs; ++i) {
        condition[i] = condition[pairs + i] = take_right[i];
        when_true[i] = right_q[i];
        when_false[i] = left_q[i];
        when_true[pairs + i] = right_id[i];
        when_false[pairs + i] = left_id[i];
    }
    const std::vector<LocalShare> chosen = ops.select(condition, when_true, when_false);

    Candidates next;
    next.valid = std::move(valid);
    next.distance.assign(chosen.begin(), chosen.begin() + static_cast<std::ptrdiff_t>(pairs));
    next.id.assign(chosen.begin() + static_cast<std::ptrdiff_t>(pairs), chosen.end());
    if (layer.valid.size() % 2 == 1) {
        next.valid.push_back(layer.valid.back());
        next.distance.push_back(layer.distance.back());
        next.id.push_back(layer.id.back());
    }
    return next;
}

// Exact private argmin over (valid, q, id) with a balanced tournament.
inline AuthorizedSelection tournament(SecureOps& ops, Candidates layer) {
    while (layer.valid.size() > 1) {
        layer = tournament_round(ops, layer);
    }

    // Mask the ID with the match bit so a no-match run opens ID 0.
    const LocalShare match = layer.valid.front();
    const std::vector<LocalShare> masked =
        ops.multiply(std::span<const LocalShare>(&match, 1),
                     std::span<const LocalShare>(&layer.id.front(), 1));
    return ops.reveal_selection(match, masked.front());
}

// q_i and R_i^2 in one multiplication round; q_i is cached for the request.
inline void squared_distances_and_radii(SecureOps& ops, const RequesterShares& requester,
                                        std::span<const StationShares> stations,
                                        std::vector<LocalShare>& q,
                                        std::vector<LocalShare>& radius_squared) {
    const std::size_t n = stations.size();
    std::vector<LocalShare> factors(3 * n);
    for (std::size_t i = 0; i < n; ++i) {
        factors[i] = SecureOps::sub(requester.x, stations[i].x);
        factors[n + i] = SecureOps::sub(requester.y, stations[i].y);
        factors[2 * n + i] = stations[i].radius;
    }
    const std::vector<LocalShare> squares = ops.multiply(factors, factors);
    q.resize(n);
    radius_squared.resize(n);
    for (std::size_t i = 0; i < n; ++i) {
        q[i] = SecureOps::add(squares[i], squares[n + i]);
        radius_squared[i] = squares[2 * n + i];
    }
}

// One bit per input, in one batch: station x, then y, then R (n of each), then
// the requester's x and y. Coordinates are shifted onto [0, 2^32) first.
inline std::vector<LocalShare> input_domain_bits(SecureOps& ops, const RequesterShares& requester,
                                                 std::span<const StationShares> stations) {
    const std::size_t n = stations.size();
    const LocalShare offset = ops.constant(kCoordinateOffset);
    std::vector<LocalShare> shifted(3 * n + 2);
    for (std::size_t i = 0; i < n; ++i) {
        shifted[i] = SecureOps::add(stations[i].x, offset);
        shifted[n + i] = SecureOps::add(stations[i].y, offset);
        shifted[2 * n + i] = stations[i].radius;
    }
    shifted[3 * n] = SecureOps::add(requester.x, offset);
    shifted[3 * n + 1] = SecureOps::add(requester.y, offset);
    return ops.fits_u32(shifted);
}

// eligible_i = in_domain_i AND [q_i <= R_i^2] AND [q_i <= D^2]
inline std::vector<LocalShare> eligibility_bits(SecureOps& ops, const RequesterShares& requester,
                                                std::span<const StationShares> stations,
                                                std::span<const LocalShare> q,
                                                std::span<const LocalShare> radius_squared,
                                                std::uint32_t horizon) {
    const std::size_t n = q.size();
    const LocalShare horizon_squared = ops.constant(Word{horizon} * horizon);
    std::vector<LocalShare> lhs(2 * n), rhs(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        lhs[i] = lhs[n + i] = q[i];
        rhs[i] = radius_squared[i];
        rhs[n + i] = horizon_squared;
    }
    const std::vector<LocalShare> within = ops.less_equal(lhs, rhs);
    const std::vector<LocalShare> fits = input_domain_bits(ops, requester, stations);

    // AND of the five bits of each station and the requester's two, as a tree
    // of three batches. Pairs: (x, y), (R, within R), (requester x, requester y).
    std::vector<LocalShare> left(2 * n + 1), right(2 * n + 1);
    for (std::size_t i = 0; i < n; ++i) {
        left[i] = fits[i];
        right[i] = fits[n + i];
        left[n + i] = fits[2 * n + i];
        right[n + i] = within[i];
    }
    left[2 * n] = fits[3 * n];
    right[2 * n] = fits[3 * n + 1];
    const std::vector<LocalShare> pairs = ops.and_bits(left, right);

    // Pairs: (coordinates, radius and within R), (within D, requester).
    std::vector<LocalShare> left_next(2 * n), right_next(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        left_next[i] = pairs[i];
        right_next[i] = pairs[n + i];
        left_next[n + i] = within[n + i];
        right_next[n + i] = pairs[2 * n];
    }
    const std::vector<LocalShare> halves = ops.and_bits(left_next, right_next);
    return ops.and_bits(std::span(halves).first(n), std::span(halves).subspan(n));
}

}  // namespace detail

inline AuthorizedSelection nearest_eligible_station(SecureOps& ops,
                                                    const RequesterShares& requester,
                                                    std::span<const StationShares> stations,
                                                    std::uint32_t horizon) {
    for (std::size_t i = 1; i < stations.size(); ++i) {
        if (stations[i].id <= stations[i - 1].id) {
            throw std::invalid_argument("stations must be sorted by strictly increasing ID");
        }
    }
    if (stations.empty()) {
        return {};  // public: nothing to search
    }

    std::vector<LocalShare> q, radius_squared;
    detail::squared_distances_and_radii(ops, requester, stations, q, radius_squared);

    detail::Candidates candidates;
    candidates.valid =  // w_i = v_i
        detail::eligibility_bits(ops, requester, stations, q, radius_squared, horizon);
    candidates.distance = q;
    candidates.id.reserve(stations.size());
    for (const StationShares& station : stations) {
        candidates.id.push_back(ops.constant(station.id));
    }
    return detail::tournament(ops, std::move(candidates));
}

}  // namespace pps

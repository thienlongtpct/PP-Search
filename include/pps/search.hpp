#pragma once

// Nearest eligible station search over secret-shared inputs.
//
//   q_i        = (A_x - P_ix)^2 + (A_y - P_iy)^2          (computed once)
//   eligible_i = [q_i <= R_i^2] AND [q_i <= D^2]
//   result     = eligible station minimising (q_i, station_id), or no match
//
// Fully oblivious: control flow, round count and every operation's size
// depend only on public values (station count N, horizon D), never on secret
// data. No intermediate value is opened; the only reconstruction is the final
// (match bit, match * selected ID) pair the output policy authorises.
//
// A private binary search with a public, padded round count first finds the
// smallest radius r* containing an eligible station; an exact tournament over
// all N stations then selects the minimum (q, id) among the eligible stations
// with q <= r*^2. Every station takes part in every round.
//
// Tie-breaking without comparing IDs: stations are processed in ascending
// public ID order, and the tournament always pairs adjacent contiguous
// ranges, so every station in a left subtree has a smaller ID than every
// station in the right subtree. Taking the right candidate only when its q is
// strictly smaller therefore yields the lexicographic minimum of (q, id),
// independent of the order in which inputs arrived.

#include "pps/secure_ops.hpp"

#include <bit>
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

// Public, fixed number of binary-search rounds for the range [0, D + 1].
inline std::uint32_t binary_search_rounds(std::uint32_t horizon) {
    return static_cast<std::uint32_t>(std::bit_width(std::uint64_t{horizon} + 1));
}

namespace detail {

struct Candidates {
    std::vector<LocalShare> valid;
    std::vector<LocalShare> distance;
    std::vector<LocalShare> id;
};

// Exact private argmin over (valid, q, id) with a balanced tournament.
inline AuthorizedSelection tournament(SecureOps& ops, Candidates layer) {
    while (layer.valid.size() > 1) {
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
        layer = std::move(next);
    }

    // Mask the ID with the match bit so a no-match run opens ID 0.
    const LocalShare match = layer.valid.front();
    const std::vector<LocalShare> masked =
        ops.multiply(std::span<const LocalShare>(&match, 1),
                     std::span<const LocalShare>(&layer.id.front(), 1));
    return ops.reveal_selection(match, masked.front());
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
    const std::size_t n = stations.size();
    if (n == 0) {
        return {};  // public: nothing to search
    }

    // q_i and R_i^2 in one multiplication round; q_i is cached for the request.
    std::vector<LocalShare> factors(3 * n);
    for (std::size_t i = 0; i < n; ++i) {
        factors[i] = SecureOps::sub(requester.x, stations[i].x);
        factors[n + i] = SecureOps::sub(requester.y, stations[i].y);
        factors[2 * n + i] = stations[i].radius;
    }
    const std::vector<LocalShare> squares = ops.multiply(factors, factors);
    std::vector<LocalShare> q(n), radius_squared(n);
    for (std::size_t i = 0; i < n; ++i) {
        q[i] = SecureOps::add(squares[i], squares[n + i]);
        radius_squared[i] = squares[2 * n + i];
    }

    // eligible_i = [q_i <= R_i^2] AND [q_i <= D^2]
    const LocalShare horizon_squared = ops.constant(Word{horizon} * horizon);
    std::vector<LocalShare> lhs(2 * n), rhs(2 * n);
    for (std::size_t i = 0; i < n; ++i) {
        lhs[i] = lhs[n + i] = q[i];
        rhs[i] = radius_squared[i];
        rhs[n + i] = horizon_squared;
    }
    const std::vector<LocalShare> within = ops.less_equal(lhs, rhs);
    const std::vector<LocalShare> eligible =
        ops.and_bits(std::span(within).first(n), std::span(within).subspan(n));

    detail::Candidates candidates;
    candidates.distance = q;
    candidates.id.reserve(n);
    for (const StationShares& station : stations) {
        candidates.id.push_back(ops.constant(station.id));
    }

    // Private binary search for r* = min { r in [0, D] : exists eligible i
    // with q_i <= r^2 }, with sentinel D + 1 meaning "no match". The round
    // count is public and padded: once low == high, `moving` is 0 and both
    // bounds stay fixed.
    LocalShare low = ops.constant(0);
    LocalShare high = ops.constant(Word{horizon} + 1);
    const std::uint32_t rounds = binary_search_rounds(horizon);
    for (std::uint32_t round = 0; round < rounds; ++round) {
        const LocalShare middle = ops.midpoint(std::span(&low, 1), std::span(&high, 1)).front();
        const LocalShare middle_squared =
            ops.multiply(std::span(&middle, 1), std::span(&middle, 1)).front();

        std::vector<LocalShare> left(n + 1), right(n + 1);
        for (std::size_t i = 0; i < n; ++i) {
            left[i] = q[i];
            right[i] = middle_squared;
        }
        left[n] = high;  // [high <= low] means converged
        right[n] = low;
        const std::vector<LocalShare> tests = ops.less_equal(left, right);
        const LocalShare moving = ops.not_bit(tests[n]);

        const LocalShare found =
            ops.reduce_or(ops.and_bits(eligible, std::span(tests).first(n)));

        const LocalShare flag_factors_a[2] = {moving, moving};
        const LocalShare flag_factors_b[2] = {found, ops.not_bit(found)};
        const std::vector<LocalShare> flags = ops.multiply(flag_factors_a, flag_factors_b);

        const LocalShare when_true[2] = {middle, ops.add_constant(middle, 1)};
        const LocalShare when_false[2] = {high, low};
        const std::vector<LocalShare> updated = ops.select(flags, when_true, when_false);
        high = updated[0];
        low = updated[1];
    }

    // Candidates are the eligible stations inside the converged radius; the
    // exact tournament then selects the minimum (q, id) among them.
    const LocalShare radius_bound = ops.multiply(std::span(&low, 1), std::span(&low, 1)).front();
    std::vector<LocalShare> bound(n, radius_bound);
    const std::vector<LocalShare> inside = ops.less_equal(q, bound);
    candidates.valid = ops.and_bits(eligible, inside);
    return detail::tournament(ops, std::move(candidates));
}

// ---- Cost planning ----------------------------------------------------------

// Replays the public control flow to count operations and synchronised
// steps. It holds no inputs and never computes on secret data; it exists so
// each party can preprocess exactly the multiplication triples a session
// consumes. Because the search is oblivious, the counts are exact for every
// input with the same (N, D), not just an upper bound.
class CostPlanner final : public SecureOps {
public:
    int party_id() const override { return 0; }

    std::vector<LocalShare> multiply(std::span<const LocalShare> x,
                                     std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        counts_.multiplications += x.size();
        ++counts_.multiply_steps;
        return std::vector<LocalShare>(x.size());
    }
    std::vector<LocalShare> less_equal(std::span<const LocalShare> x,
                                       std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        counts_.comparisons += x.size();
        ++counts_.compare_steps;
        return std::vector<LocalShare>(x.size());
    }
    std::vector<LocalShare> halve(std::span<const LocalShare> x) override {
        counts_.halvings += x.size();
        ++counts_.halve_steps;
        return std::vector<LocalShare>(x.size());
    }
    AuthorizedSelection reveal_selection(const LocalShare&, const LocalShare&) override {
        ++counts_.reveal_steps;
        return {};
    }

    const OperationCounts& counts() const { return counts_; }

private:
    OperationCounts counts_;
};

inline OperationCounts plan_search(std::size_t station_count, std::uint32_t horizon) {
    CostPlanner planner;
    std::vector<StationShares> stations(station_count);
    for (std::size_t i = 0; i < station_count; ++i) {
        stations[i].id = i + 1;
    }
    nearest_eligible_station(planner, RequesterShares{}, stations, horizon);
    return planner.counts();
}

}  // namespace pps

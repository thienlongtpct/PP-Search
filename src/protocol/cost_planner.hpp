#pragma once

// Exact cost planning from the public station count.

#include "protocol/search.hpp"

#include <cstddef>
#include <vector>

namespace pps {

// Replays the public control flow to count operations and synchronised
// steps. It holds no inputs and never computes on secret data; it exists so
// each party can preprocess exactly the multiplication triples a session
// consumes. Because the search is oblivious, the counts are exact for every
// input and horizon with the same N, not just an upper bound. For N >= 1 they
// are M = 13N - 3 multiplications, C = 3N - 1 comparisons and K = 3N + 2 input
// range checks; N = 0 is public and runs nothing.
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
    std::vector<LocalShare> fits_u32(std::span<const LocalShare> x) override {
        counts_.range_checks += x.size();
        ++counts_.range_check_steps;
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

inline OperationCounts plan_search(std::size_t station_count) {
    CostPlanner planner;
    std::vector<StationShares> stations(station_count);
    for (std::size_t i = 0; i < station_count; ++i) {
        stations[i].id = i + 1;
    }
    nearest_eligible_station(planner, RequesterShares{}, stations, 0);
    return planner.counts();
}

}  // namespace pps

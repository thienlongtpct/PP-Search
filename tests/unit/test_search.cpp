// The search and its cost plan, on the test-only plaintext reference evaluator.

#include "protocol/cost_planner.hpp"
#include "support/check.hpp"
#include "support/plaintext_oracle.hpp"
#include "support/plaintext_reference_ops.hpp"
#include "unit/unit_tests.hpp"

#include <algorithm>
#include <random>

using namespace pps;

namespace {

// Tournament levels: ceil(log2 n) with the odd entry carried forward.
std::uint64_t tournament_levels(std::uint64_t n) {
    std::uint64_t levels = 0;
    for (; n > 1; n = n - n / 2) {
        ++levels;
    }
    return levels;
}

}  // namespace

void test_cost_plan() {
    for (const std::uint64_t n : {1u, 2u, 3u, 4u, 5u, 7u, 8u, 9u, 64u, 65u, 1024u}) {
        const OperationCounts plan = plan_search(n);
        CHECK(plan.multiplications == 13 * n - 3);
        CHECK(plan.comparisons == 3 * n - 1);
        CHECK(plan.range_checks == 3 * n + 2);
        CHECK(plan.range_check_steps == 1);
        // Squares; three batches to AND the eligibility bits; three per level; output mask.
        CHECK(plan.multiply_steps == 4 + 3 * tournament_levels(n) + 1);
        // Both range checks; one batch per level.
        CHECK(plan.compare_steps == 1 + tournament_levels(n));
        CHECK(plan.reveal_steps == 1);
    }
    CHECK(tournament_levels(1) == 0 && tournament_levels(5) == 3 && tournament_levels(1024) == 10);
    // No secure work at all for the public empty search; 13n - 3 starts at n = 1.
    CHECK(plan_search(0).multiplications == 0 && plan_search(0).range_checks == 0 &&
          plan_search(0).reveal_steps == 0);

    // The horizon only enters as a public comparison operand.
    const std::vector<StationShares> stations(5);
    std::vector<StationShares> ordered = stations;
    for (std::size_t i = 0; i < ordered.size(); ++i) {
        ordered[i].id = i + 1;
    }
    for (const std::uint32_t horizon : {0u, 1u, 100u, 1'000'000u, 0xffffffffu}) {
        CostPlanner planner;
        nearest_eligible_station(planner, RequesterShares{}, ordered, horizon);
        const OperationCounts& counts = planner.counts();
        const OperationCounts plan = plan_search(ordered.size());
        CHECK(counts.multiplications == plan.multiplications &&
              counts.comparisons == plan.comparisons &&
              counts.range_checks == plan.range_checks &&
              counts.multiply_steps == plan.multiply_steps &&
              counts.compare_steps == plan.compare_steps && counts.reveal_steps == 1);
    }
}

namespace {

testing::PlaintextReferenceOps::Trace reference_trace(std::int32_t ax, std::int32_t ay,
                                                      const std::vector<PlainStation>& stations,
                                                      std::uint32_t horizon) {
    testing::PlaintextReferenceOps ops;
    std::vector<StationShares> shares;
    for (const PlainStation& s : stations) {
        shares.push_back({s.id, {encode_coordinate(s.x)}, {encode_coordinate(s.y)},
                          {encode_radius(s.support_radius)}});
    }
    nearest_eligible_station(ops, {{encode_coordinate(ax)}, {encode_coordinate(ay)}}, shares, horizon);
    return ops.trace();
}

}  // namespace

void test_schedule_independence() {
    for (const std::size_t n : {1u, 2u, 3u, 5u, 8u, 13u}) {
        const auto make = [n](auto station) {
            std::vector<PlainStation> stations;
            for (std::size_t i = 0; i < n; ++i) {
                stations.push_back(station(i));
            }
            return stations;
        };
        const auto id = [](std::size_t i) { return static_cast<std::uint64_t>(i * 2 + 1); };
        const std::vector<std::vector<PlainStation>> patterns{
            make([&](std::size_t i) { return PlainStation{id(i), 1000, 0, 0}; }),  // none eligible
            make([&](std::size_t i) { return PlainStation{id(i), 1, 0, 50}; }),    // all tied
            make([&](std::size_t i) {  // only the last one eligible
                return PlainStation{id(i), 5, 0, i + 1 == n ? 50u : 0u};
            }),
            make([&](std::size_t i) {  // alternating, distinct distances
                return PlainStation{id(i), static_cast<std::int32_t>(i) + 1, 0, i % 2 ? 50u : 0u};
            }),
        };
        const auto expected = reference_trace(0, 0, patterns[0], 100);
        std::uint64_t products = 0, comparisons = 0, range_checks = 0, reveals = 0;
        for (const auto& [operation, size] : expected) {
            products += operation == '*' ? size : 0;
            comparisons += operation == '<' ? size : 0;
            range_checks += operation == 'r' ? size : 0;
            reveals += operation == '!' ? 1 : 0;
            CHECK(operation == '*' || operation == '<' || operation == 'r' || operation == '!');
        }
        CHECK(products == 13 * n - 3 && comparisons == 3 * n - 1 && range_checks == 3 * n + 2 &&
              reveals == 1);
        CHECK(expected.back().first == '!');  // the one opening comes last
        for (const auto& pattern : patterns) {
            for (const std::uint32_t horizon : {0u, 1u, 100u, 0xffffffffu}) {
                // A schedule check on the reference evaluator, not a security proof.
                CHECK(reference_trace(0, 0, pattern, horizon) == expected);
            }
        }
    }
}

namespace {

PlainSelection run_reference(std::int32_t ax, std::int32_t ay, std::vector<PlainStation> stations,
                             std::uint32_t horizon) {
    std::sort(stations.begin(), stations.end(),
              [](const PlainStation& a, const PlainStation& b) { return a.id < b.id; });
    testing::PlaintextReferenceOps ops;
    std::vector<StationShares> shares;
    for (const PlainStation& s : stations) {
        shares.push_back({s.id, {encode_coordinate(s.x)}, {encode_coordinate(s.y)},
                          {encode_radius(s.support_radius)}});
    }
    const AuthorizedSelection result = nearest_eligible_station(
        ops, {{encode_coordinate(ax)}, {encode_coordinate(ay)}}, shares, horizon);

    // Obliviousness: the same N and D with all-zero inputs runs exactly the
    // same sequence of interactive operations with the same batch sizes.
    testing::PlaintextReferenceOps zero_ops;
    std::vector<StationShares> zeros(shares.size());
    for (std::size_t i = 0; i < zeros.size(); ++i) {
        zeros[i].id = shares[i].id;
    }
    nearest_eligible_station(zero_ops, RequesterShares{}, zeros, horizon);
    if (ops.trace() != zero_ops.trace()) {
        throw std::runtime_error("search control flow depends on secret inputs");
    }
    return {result.match, result.station_id};
}

void check_search(std::int32_t ax, std::int32_t ay, const std::vector<PlainStation>& stations,
                  std::uint32_t horizon) {
    const PlainSelection expected = plain_nearest_eligible(ax, ay, stations, horizon);
    if (!(run_reference(ax, ay, stations, horizon) == expected)) {
        throw std::runtime_error("search logic disagrees with the plaintext oracle");
    }
}

}  // namespace

void test_search_logic() {
    check_search(0, 0, {{10, 2, 0, 10}, {20, 1, 1, 10}}, 100);
    check_search(0, 0, {{1, 100, 0, 100}}, 100);              // exactly at D
    check_search(0, 0, {{1, 101, 0, 1000}}, 100);             // D + 1
    check_search(0, 0, {{1, 1, 0, 0}, {2, 5, 0, 10}}, 100);   // closer but radius too small
    check_search(0, 0, {{9, 3, 4, 5}, {4, -3, -4, 5}}, 10);   // tie -> smaller ID
    check_search(0, 0, {{4, -3, -4, 5}, {9, 3, 4, 5}}, 10);   // reversed insertion order
    check_search(0, 0, {}, 10);
    check_search(0, 0, {{1, 5, 5, 1}, {2, 6, 6, 2}}, 100);    // all ineligible
    check_search(7, 7, {{3, 7, 7, 0}}, 0);                    // zero distance, zero radius
    check_search(7, 7, {{8, 7, 7, 0}, {3, 7, 7, 0}, {5, 7, 7, 0}}, 0);  // D = 0, three-way tie
    check_search(0, 0, {{6, 0, 10, 10}, {2, 10, 0, 10}, {4, -10, 0, 10}}, 10);  // ties at D^2
    check_search(0, 0, {{6, 0, 3, 9}, {2, 3, 0, 9}, {4, 0, 1, 0}, {1, 5, 5, 9}}, 1000);  // tie behind a closer ineligible station

    // One station, each way.
    CHECK(run_reference(0, 0, {{7, 3, 4, 5}}, 5) == (PlainSelection{true, 7}));
    CHECK(run_reference(0, 0, {{7, 3, 4, 4}}, 5) == PlainSelection{});

    // Support-radius and horizon boundaries are inclusive, off the axes too.
    CHECK(run_reference(0, 0, {{1, 3, 4, 5}}, 1000) == (PlainSelection{true, 1}));  // q = R^2
    CHECK(run_reference(0, 0, {{1, 3, 4, 4}}, 1000) == PlainSelection{});           // q = (R+1)^2
    CHECK(run_reference(0, 0, {{1, 5, 1, 5}}, 1000) == PlainSelection{});           // q = R^2 + 1
    CHECK(run_reference(0, 0, {{1, 3, 4, 1000}}, 5) == (PlainSelection{true, 1}));  // q = D^2
    CHECK(run_reference(0, 0, {{1, 5, 1, 1000}}, 5) == PlainSelection{});           // q = D^2 + 1
    CHECK(run_reference(0, 0, {{1, 3, 4, 5}}, 5) == (PlainSelection{true, 1}));     // q = R^2 = D^2

    // D = 0 only admits a station at the requester's own location.
    CHECK(run_reference(9, -9, {{1, 9, -9, 7}, {2, 9, -8, 7}}, 0) == (PlainSelection{true, 1}));
    CHECK(run_reference(9, -9, {{1, 10, -9, 7}, {2, 9, -8, 7}}, 0) == PlainSelection{});

    // Odd station counts: the carried last entry can win, lose and tie.
    CHECK(run_reference(0, 0, {{1, 9, 0, 99}, {2, 8, 0, 99}, {3, 1, 0, 99}}, 99) ==
          (PlainSelection{true, 3}));
    CHECK(run_reference(0, 0, {{1, 1, 0, 99}, {2, 8, 0, 99}, {3, 1, 0, 99}}, 99) ==
          (PlainSelection{true, 1}));
    CHECK(run_reference(0, 0, {{1, 9, 0, 99}, {2, 8, 0, 99}, {3, 1, 0, 0}}, 99) ==
          (PlainSelection{true, 2}));
    CHECK(run_reference(0, 0, {{1, 0, 2, 99}, {2, 2, 0, 99}, {3, 0, -2, 99}, {4, -2, 0, 99}, {5, 2, 0, 99}},
                        99) == (PlainSelection{true, 1}));
    CHECK(run_reference(0, 0, {{1, 9, 0, 0}, {2, 8, 0, 0}, {3, 7, 0, 0}, {4, 6, 0, 0}, {5, 5, 0, 5}}, 99) ==
          (PlainSelection{true, 5}));

    // Signed coordinate extremes with the maximum radii and horizon. The
    // largest squared distance exceeds D^2; a full single-axis span equals it.
    const std::int32_t lowest = static_cast<std::int32_t>(kCoordinateMin);
    const std::int32_t highest = static_cast<std::int32_t>(kCoordinateMax);
    const std::uint32_t widest = static_cast<std::uint32_t>(kRadiusMax);
    CHECK(run_reference(lowest, 0, {{1, highest, 0, widest}}, 0xffffffffu) == (PlainSelection{true, 1}));
    CHECK(run_reference(highest, 0, {{1, lowest, 0, widest}}, 0xffffffffu) == (PlainSelection{true, 1}));
    CHECK(run_reference(0, lowest, {{1, 0, highest, widest}}, 0xffffffffu) == (PlainSelection{true, 1}));
    CHECK(run_reference(lowest, 0, {{1, highest, 0, widest - 1}}, 0xffffffffu) == PlainSelection{});
    CHECK(run_reference(lowest, 0, {{1, highest, 0, widest}}, 0xfffffffeu) == PlainSelection{});
    CHECK(run_reference(lowest, lowest, {{1, highest, highest, widest}}, 0xffffffffu) == PlainSelection{});
    CHECK(run_reference(lowest, lowest, {{1, highest, highest, widest}, {2, highest, lowest, widest}},
                        0xffffffffu) == (PlainSelection{true, 2}));
    check_search(highest, lowest, {{4, lowest, highest, widest}, {6, lowest, lowest, widest},
                                   {8, highest, highest, widest}, {9, highest, lowest, 0}},
                 0xffffffffu);
    check_search(kCoordinateMin, kCoordinateMin,
                     {{1, static_cast<std::int32_t>(kCoordinateMax), static_cast<std::int32_t>(kCoordinateMax),
                       static_cast<std::uint32_t>(kRadiusMax)}},
                     0xffffffffu);                                 // extreme: q ~ 2^65 > D^2
    check_search(kCoordinateMin, 0,
                     {{1, static_cast<std::int32_t>(kCoordinateMin + 0xfffffffeLL), 0,
                       static_cast<std::uint32_t>(kRadiusMax)}},
                     0xffffffffu);                                 // largest in-range distance

    std::mt19937_64 random(12345);  // deterministic seed: plaintext test data only
    for (int trial = 0; trial < 3000; ++trial) {
        const auto coordinate = [&] { return static_cast<std::int32_t>(random() % 61) - 30; };
        const std::uint32_t horizon = static_cast<std::uint32_t>(random() % 45);
        std::vector<PlainStation> stations;
        const std::size_t count = random() % 12;
        std::vector<std::uint64_t> ids(40);
        for (std::size_t i = 0; i < ids.size(); ++i) {
            ids[i] = i * 3 + 1;
        }
        std::shuffle(ids.begin(), ids.end(), random);
        for (std::size_t i = 0; i < count; ++i) {
            stations.push_back({ids[i], coordinate(), coordinate(),
                                static_cast<std::uint32_t>(random() % 40)});
        }
        check_search(coordinate(), coordinate(), stations, horizon);
    }

    // Wide coordinates and horizons: near-ties and exact ties.
    for (int trial = 0; trial < 1000; ++trial) {
        const std::int32_t spread = trial % 2 == 0 ? 2'000'000 : 64;
        const auto coordinate = [&] {
            return static_cast<std::int32_t>(random() % (2 * spread + 1)) - spread;
        };
        const std::uint32_t horizon = static_cast<std::uint32_t>(random() % (4u * spread));
        std::vector<PlainStation> stations;
        const std::size_t count = random() % 20;
        for (std::size_t i = 0; i < count; ++i) {
            stations.push_back({i * 7 + 2, coordinate(), coordinate(),
                                static_cast<std::uint32_t>(random() % (4u * spread))});
        }
        check_search(coordinate(), coordinate(), stations, horizon);
    }
}

void test_out_of_domain_inputs() {
    using Ops = testing::PlaintextReferenceOps;
    const auto power = [](int bits) { return Word{1} << bits; };
    const Word all_ones = ~Word{0};

    // Words just outside a domain, words that match an in-domain value in the
    // bits a comparison reads, and large values.
    const std::vector<Word> bad_coordinates{
        power(31), encode_signed(kCoordinateMin - 1), power(32), power(34), power(66), power(67),
        power(68), power(68) + 1000, power(100) + 1, power(127), power(127) + power(31), all_ones - power(31)};
    const std::vector<Word> bad_radii{power(32), power(32) + 1, power(34), power(67), power(68) + 5,
                                      power(127), all_ones};

    const std::int32_t ax = 1000, ay = 0;
    const std::uint32_t horizon = 100'000;
    const RequesterShares requester{{encode_coordinate(ax)}, {encode_coordinate(ay)}};
    const StationShares honest_far{10, {encode_coordinate(990)}, {encode_coordinate(0)}, {encode_radius(100)}};
    const StationShares honest_near{20, {encode_coordinate(995)}, {encode_coordinate(0)}, {encode_radius(100)}};

    // Runs three stations in ID order; the schedule must match all-zero inputs.
    const auto run = [&](const RequesterShares& who, const StationShares& dishonest) {
        std::vector<StationShares> shares{honest_far, honest_near, dishonest};
        std::sort(shares.begin(), shares.end(),
                  [](const StationShares& a, const StationShares& b) { return a.id < b.id; });
        Ops ops(Ops::Inputs::kDishonest);
        const AuthorizedSelection result = nearest_eligible_station(ops, who, shares, horizon);
        std::vector<StationShares> zeros(shares.size());
        for (std::size_t i = 0; i < zeros.size(); ++i) {
            zeros[i].id = shares[i].id;
        }
        Ops zero_ops(Ops::Inputs::kDishonest);
        nearest_eligible_station(zero_ops, RequesterShares{}, zeros, horizon);
        CHECK(ops.trace() == zero_ops.trace());
        return result;
    };
    // Wherever it sits in the tournament, the honest selection must stand.
    const auto check_excluded = [&](StationShares dishonest) {
        for (const std::uint64_t id : {5u, 15u, 25u}) {
            dishonest.id = id;
            const AuthorizedSelection result = run(requester, dishonest);
            CHECK(result.match && result.station_id == honest_near.id);
        }
    };

    // At the requester's own location with a valid radius, so an in-domain
    // station with these fields would win.
    const StationShares closest{5, {encode_coordinate(ax)}, {encode_coordinate(ay)}, {encode_radius(100)}};
    const AuthorizedSelection control = run(requester, closest);
    CHECK(control.match && control.station_id == closest.id);

    for (const Word bad : bad_coordinates) {
        StationShares station = closest;
        station.x.value = bad;
        check_excluded(station);
        station = closest;
        station.y.value = bad;
        check_excluded(station);
    }
    for (const Word bad : bad_radii) {
        StationShares station = closest;
        station.radius.value = bad;
        check_excluded(station);
    }

    // A requester input outside its domain gives no match at all.
    for (const Word bad : bad_coordinates) {
        for (const RequesterShares& who : {RequesterShares{{bad}, requester.y}, RequesterShares{requester.x, {bad}}}) {
            const AuthorizedSelection result = run(who, closest);
            CHECK(!result.match && result.station_id == 0);
        }
    }

    // Random ring elements of every magnitude never change the selection.
    std::mt19937_64 random(54321);  // deterministic seed: plaintext test data only
    const auto word = [&] { return (Word{random()} << 64) | random(); };
    const auto in_domain = [](Word shifted) { return (shifted >> kInputBits) == 0; };
    for (int trial = 0; trial < 2000; ++trial) {
        const int shift = static_cast<int>(random() % 96);
        const StationShares station{5, {word() >> shift}, {word() >> shift}, {word() >> shift}};
        if (!in_domain(station.x.value + kCoordinateOffset) || !in_domain(station.y.value + kCoordinateOffset) ||
            !in_domain(station.radius.value)) {
            check_excluded(station);
        }
    }

    // The limits of each domain stay valid inputs.
    for (const auto& [x, y] : {std::pair<std::int64_t, std::int64_t>{kCoordinateMin, kCoordinateMin},
                               {kCoordinateMax, kCoordinateMax},
                               {kCoordinateMin, kCoordinateMax}}) {
        Ops ops;
        const StationShares station{1, {encode_coordinate(x)}, {encode_coordinate(y)}, {encode_radius(kRadiusMax)}};
        const AuthorizedSelection result = nearest_eligible_station(
            ops, {{encode_coordinate(x)}, {encode_coordinate(y)}}, std::span(&station, 1), 0);
        CHECK(result.match && result.station_id == 1);
    }
}

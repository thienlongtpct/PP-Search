// Dedicated two-process test harness for the MP-SPDZ backend (run by
// tests/integration/test_preprocessing.py as two separate processes).
//
// Linked against pps_mpspdz_test_harness, the only build of the backend that
// contains open_triples_for_test_harness. pp_party never contains it.
// Also checks the input range check, and the search with out-of-domain inputs,
// on the real backend.
//
// Usage: test_preprocessing <party-id> <mpc-port-base>   (cwd = party runtime dir)

#include "support/check.hpp"

#include "common/errors.hpp"
#include "backend/mpspdz_party.hpp"
#include "protocol/cost_planner.hpp"

#include <iostream>
#include <set>
#include <string>
#include <utility>

namespace {

using namespace pps;

// An additive sharing of `value` under a public test mask, so that carries
// between the two shares are exercised.
LocalShare split(const MpSpdzParty& party, Word value, Word mask) {
    return {party.party_id() == 0 ? mask : value - mask};
}

Word open_value(MpSpdzParty& party, LocalShare value) {
    return party.open_for_test_harness(std::span(&value, 1)).front();
}

void run(int party_id, int port_base) {
    MpSpdzParty party({party_id, {"localhost", "localhost"}, port_base});

    // 1. Triple relation c = a * b (mod 2^128) on OT-generated triples.
    party.generate_triples(64);
    CHECK(party.triples_remaining() == 64);
    const auto opened = party.open_triples_for_test_harness(32);
    CHECK(party.triples_remaining() == 32);
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen;
    for (const auto& triple : opened) {
        CHECK(triple[2] == triple[0] * triple[1]);
        CHECK(seen.insert({static_cast<std::uint64_t>(triple[0] >> 64),
                           static_cast<std::uint64_t>(triple[0])}).second);
    }

    // 2. Beaver multiplication consumes exactly one triple per product.
    const LocalShare one = party.constant(1);
    const LocalShare six = party.constant(6), seven = party.constant(7);
    CHECK(open_value(party, party.multiply(std::span(&six, 1), std::span(&seven, 1)).front()) == 42);
    CHECK(party.triples_remaining() == 31);
    std::vector<LocalShare> xs(31, party.constant(3)), ys(31, party.constant(5));
    const std::vector<LocalShare> products = party.multiply(xs, ys);
    CHECK(products.size() == 31);
    CHECK(party.triples_remaining() == 0);

    // 3. Exhaustion: no fallback, no reuse.
    bool exhausted = false;
    try {
        party.multiply(std::span(&one, 1), std::span(&one, 1));
    } catch (const PreprocessingExhausted&) {
        exhausted = true;
    }
    CHECK(exhausted);
    CHECK(party.triples_remaining() == 0);

    // 4. New triples replace the store and are fresh.
    party.generate_triples(40);
    for (const auto& triple : party.open_triples_for_test_harness(4)) {
        CHECK(triple[2] == triple[0] * triple[1]);
        CHECK(seen.insert({static_cast<std::uint64_t>(triple[0] >> 64),
                           static_cast<std::uint64_t>(triple[0])}).second);
    }

    // 5. Exported comparison at the domain boundaries.
    const Word top = (Word{1} << kComparisonOperandBits) - 1;
    const std::vector<LocalShare> left{party.constant(0), party.constant(top), party.constant(top),
                                       party.constant(top - 1), party.constant(5)};
    const std::vector<LocalShare> right{party.constant(0), party.constant(top - 1),
                                        party.constant(top), party.constant(top), party.constant(0)};
    const std::vector<LocalShare> bits = party.less_equal(left, right);
    std::vector<Word> expected_bits{1, 0, 1, 1, 0};
    CHECK(party.open_for_test_harness(bits) == expected_bits);

    // 6. The authorised reveal opens (match, match * id) and rejects values
    //    outside that domain on both parties.
    const AuthorizedSelection selected = party.reveal_selection(one, party.constant(42));
    CHECK(selected.match && selected.station_id == 42);
    const AuthorizedSelection none = party.reveal_selection(party.constant(0), party.constant(0));
    CHECK(!none.match && none.station_id == 0);
    for (const auto& [match, id] : {std::pair<Word, Word>{2, 0}, {0, 42}, {1, Word{1} << 64}}) {
        bool rejected = false;
        try {
            party.reveal_selection(party.constant(match), party.constant(id));
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        CHECK(rejected);
    }
    CHECK(party.triples_remaining() == 36);
    std::uint64_t triples_requested = 104;

    // 7. The exported range check at its boundaries and across the whole ring.
    //    It uses MP-SPDZ's own comparison preprocessing, not the stored triples.
    const auto power = [](int bits) { return Word{1} << bits; };
    const Word all_ones = ~Word{0};
    const std::vector<std::pair<Word, Word>> range_cases{
        {0, 1}, {1, 1}, {power(31), 1}, {power(32) - 1, 1},
        {power(32), 0}, {power(32) + 1, 0}, {power(33), 0}, {power(34), 0}, {power(63), 0},
        {power(64), 0}, {power(66), 0}, {power(67), 0}, {power(68), 0}, {power(68) + 1, 0},
        {power(100), 0}, {power(126), 0}, {power(127) - 1, 0}, {power(127), 0}, {power(127) + 1, 0},
        {power(127) + power(32), 0}, {all_ones - power(32), 0}, {all_ones - power(32) + 1, 0},
        {all_ones - 1, 0}, {all_ones, 0}};
    const std::vector<Word> masks{0, 1, all_ones, power(127), power(32) - 1,
                                  (Word{0x0123456789abcdefULL} << 64) | 0xfedcba9876543210ULL};
    for (const Word mask : masks) {
        std::vector<LocalShare> shares;
        std::vector<Word> expected;
        for (const auto& [value, fits] : range_cases) {
            shares.push_back(split(party, value, mask));
            expected.push_back(fits);
        }
        CHECK(party.open_for_test_harness(party.fits_u32(shares)) == expected);
    }

    // 8. The whole search on the real backend with out-of-domain inputs.
    const Word mask = (Word{0xdeadbeefULL} << 64) | 0x0badf00dULL;
    const auto share = [&](std::int64_t value) { return split(party, encode_coordinate(value), mask); };
    const auto station = [&](std::uint64_t id, std::int64_t x) {
        return StationShares{id, share(x), share(0), split(party, encode_radius(100000), mask)};
    };
    const auto search = [&](RequesterShares requester, const std::vector<StationShares>& stations) {
        const std::uint64_t triples = plan_search(stations.size()).multiplications;
        party.generate_triples(triples);
        triples_requested += triples;
        const AuthorizedSelection result = nearest_eligible_station(party, requester, stations, 100000);
        CHECK(party.triples_remaining() == 0);
        return result;
    };
    const RequesterShares requester{share(1000), share(0)};
    // Control: in its domain, station 2 is the nearest.
    AuthorizedSelection found = search(requester, {station(1, 900), station(2, 1000), station(3, 800)});
    CHECK(found.match && found.station_id == 2);
    for (const Word bad : {power(31), power(32), power(34), power(67), power(68) + 1000, power(127),
                           all_ones - power(31)}) {
        StationShares dishonest = station(2, 1000);
        dishonest.x = split(party, bad, mask);
        found = search(requester, {station(1, 900), dishonest, station(3, 800)});
        CHECK(found.match && found.station_id == 1);
        dishonest = station(2, 1000);
        dishonest.y = split(party, bad, mask);
        found = search(requester, {station(1, 900), dishonest, station(3, 800)});
        CHECK(found.match && found.station_id == 1);
        found = search({split(party, bad, mask), share(0)}, {station(1, 900), station(2, 1000)});
        CHECK(!found.match && found.station_id == 0);
    }
    for (const Word bad : {power(32), power(34), power(68) + 5, power(127), all_ones}) {
        StationShares dishonest = station(2, 1000);
        dishonest.radius = split(party, bad, mask);
        found = search(requester, {station(1, 900), dishonest, station(3, 800)});
        CHECK(found.match && found.station_id == 1);
    }

    const BackendStats stats = party.finish();
    CHECK(stats.triples_requested == triples_requested);
    std::cout << "party " << party_id << ": preprocessing harness passed (offline "
              << stats.offline.bytes_sent << " bytes sent)" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: test_preprocessing <party-id> <mpc-port-base>\n";
        return 64;
    }
    try {
        run(std::stoi(argv[1]), std::stoi(argv[2]));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAILED: " << error.what() << std::endl;
        return 1;
    }
}

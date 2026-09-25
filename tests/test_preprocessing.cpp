// Dedicated two-process test harness for the MP-SPDZ backend (run by
// tests/integration/test_preprocessing.py as two separate processes).
//
// Linked against pps_mpspdz_test_harness, the only build of the backend that
// contains open_triples_for_test_harness. pp_party never contains it.
//
// Usage: test_preprocessing <party-id> <mpc-port-base>   (cwd = party runtime dir)

#include "check.hpp"

#include "pps/errors.hpp"
#include "pps/mpspdz_party.hpp"

#include <iostream>
#include <set>
#include <string>

namespace {

using namespace pps;

// Opens a bit b and a value v < 2^64 through the authorised reveal path.
AuthorizedSelection open_pair(MpSpdzParty& party, LocalShare bit, LocalShare value) {
    const std::vector<LocalShare> masked = party.multiply(std::span(&bit, 1), std::span(&value, 1));
    return party.reveal_selection(bit, masked.front());
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
    const AuthorizedSelection product = open_pair(party, one, party.constant(6 * 7));
    CHECK(product.match && product.station_id == 42);
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

    // 5. Exported comparison and truncation at the domain boundaries.
    const Word top = (Word{1} << kComparisonOperandBits) - 1;
    const std::vector<LocalShare> left{party.constant(0), party.constant(top), party.constant(top),
                                       party.constant(top - 1), party.constant(5)};
    const std::vector<LocalShare> right{party.constant(0), party.constant(top - 1),
                                        party.constant(top), party.constant(top), party.constant(0)};
    const std::vector<LocalShare> bits = party.less_equal(left, right);
    const bool expected[] = {true, false, true, true, false};
    for (std::size_t i = 0; i < bits.size(); ++i) {
        const AuthorizedSelection opened_bit = open_pair(party, bits[i], one);
        CHECK(opened_bit.match == expected[i]);
    }
    const std::vector<LocalShare> halves =
        party.halve(std::vector<LocalShare>{party.constant(15), party.constant(0),
                                            party.constant((Word{1} << 64) + 1)});
    CHECK(open_pair(party, one, halves[0]).station_id == 7);
    CHECK(!open_pair(party, halves[1], halves[1]).match);  // floor(0/2) = 0
    CHECK(open_pair(party, one, halves[2]).station_id == (std::uint64_t{1} << 63));

    const BackendStats stats = party.finish();
    CHECK(stats.triples_requested == 104);
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

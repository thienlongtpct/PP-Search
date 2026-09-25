#pragma once

// SecureOps implemented with MP-SPDZ's semi2k protocol (semi-honest,
// dishonest-majority, additive secret sharing over Z_(2^128)).
//
// * Party-to-party traffic runs over MP-SPDZ's CryptoPlayer: mutually
//   authenticated TLS with certificates P0/P1 in <runtime>/Player-Data.
// * multiply: MP-SPDZ's Beaver protocol, fed from a finite store of
//   multiplication triples produced by MP-SPDZ's OT-based semi2k triple
//   generator (SemiPrep2k / OTTripleGenerator) in an explicit offline phase.
//   Each triple is consumed exactly once; an empty store throws
//   PreprocessingExhausted (no fallback).
// * less_equal / halve: MP-SPDZ-compiled functions (mpc/pp_ops.py) called
//   through Machine::run_function. They use MP-SPDZ's exact ring comparison
//   and truncation (local share splitting into binary shares plus binary
//   circuits with OT-generated binary triples and daBits).
//
// The implementation lives in src/mpspdz_party.cpp, the only translation unit
// that includes MP-SPDZ headers. The process working directory must be the
// party's runtime directory (Programs/ and Player-Data/).
//
// MP-SPDZ supports one virtual machine per process (BaseMachine keeps a
// process-wide singleton, and CryptoPlayer connection IDs cannot be reused),
// so a party process creates exactly one MpSpdzParty and runs its sessions
// sequentially on it. start_session() empties the Beaver triple store, which
// is refilled with exactly the session's requirement. MP-SPDZ's worker thread
// keeps its own consume-once buffers of comparison preprocessing (binary
// triples, daBits) for the lifetime of the process; leftover elements of a
// batch may be consumed by a later session, but no element is used twice.

#include "pps/secure_ops.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace pps {

struct MpSpdzConfig {
    int party_id = 0;
    std::vector<std::string> hosts;  // MP-SPDZ player hosts, index = party ID
    int port_base = 0;               // player i listens on port_base + i
};

struct PhaseCost {
    double seconds = 0;
    std::uint64_t bytes_sent = 0;  // by this party (= received by the peer)
    std::uint64_t rounds = 0;      // MP-SPDZ-counted send/exchange rounds
};

struct BackendStats {
    PhaseCost connect;       // TLS setup of the MP-SPDZ player (once per process)
    PhaseCost offline;       // base OTs + Beaver triple generation
    PhaseCost online;        // everything after inputs are loaded
    std::uint64_t triples_requested = 0;
    std::uint64_t triples_consumed = 0;
    std::uint64_t triples_remaining = 0;
};

class MpSpdzParty final : public SecureOps {
public:
    explicit MpSpdzParty(const MpSpdzConfig& config);
    ~MpSpdzParty() override;
    MpSpdzParty(const MpSpdzParty&) = delete;
    MpSpdzParty& operator=(const MpSpdzParty&) = delete;

    int party_id() const override { return party_id_; }

    // Begins a new session: discards any stored triples and resets the
    // per-session statistics.
    void start_session();

    // Offline phase: generate `count` fresh multiplication triples with the
    // peer. Any previously stored triples are discarded, never reused.
    void generate_triples(std::uint64_t count);
    std::uint64_t triples_remaining() const;
    // Marks the end of the offline phase and the start of the online phase.
    void begin_online();

    std::vector<LocalShare> multiply(std::span<const LocalShare> x,
                                     std::span<const LocalShare> y) override;
    std::vector<LocalShare> less_equal(std::span<const LocalShare> x,
                                       std::span<const LocalShare> y) override;
    std::vector<LocalShare> halve(std::span<const LocalShare> x) override;
    AuthorizedSelection reveal_selection(const LocalShare& match,
                                         const LocalShare& station_id) override;

    // Ends the session and returns its statistics. The online cost includes
    // the comparison preprocessing MP-SPDZ generates on demand.
    BackendStats finish();

#ifdef PPS_TEST_HARNESS
    // Compiled only into the dedicated preprocessing test harness
    // (tests/test_preprocessing.cpp), never into pp_party: opens stored
    // triples to both parties so that c = a * b can be checked.
    std::vector<std::array<Word, 3>> open_triples_for_test_harness(std::uint64_t count);
#endif

private:
    struct Impl;
    int party_id_;
    std::unique_ptr<Impl> impl_;
};

}  // namespace pps

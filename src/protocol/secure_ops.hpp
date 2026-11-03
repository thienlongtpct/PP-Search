#pragma once

// Party-local secure operations for one computation party.
//
// A LocalShare is this party's single additive share of a value in Z_(2^128):
// value = share_party0 + share_party1 mod 2^128. A process never holds the
// other party's share. Boolean values are shares of 0/1 in the same ring, so
// AND is multiplication, NOT is 1 - a and OR is a + b - ab.
//
// Linear operations are local. Interactive operations are batched: one call
// is one synchronised protocol step with the peer party, executed by the
// MP-SPDZ semi2k backend. There is intentionally no generic "open" operation;
// the only reconstruction is reveal_selection, which opens exactly the two
// values the output policy authorises (match bit and selected station ID).

#include "common/ring.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace pps {

struct LocalShare {
    Word value = 0;
};

struct AuthorizedSelection {
    bool match = false;
    std::uint64_t station_id = 0;
};

// Operations executed by one party (or counted by a planner). Each batched
// call is one step; the element counts are summed.
struct OperationCounts {
    std::uint64_t multiplications = 0;
    std::uint64_t comparisons = 0;
    std::uint64_t range_checks = 0;
    std::uint64_t multiply_steps = 0;
    std::uint64_t compare_steps = 0;
    std::uint64_t range_check_steps = 0;
    std::uint64_t reveal_steps = 0;
};

class SecureOps {
public:
    virtual ~SecureOps() = default;

    virtual int party_id() const = 0;

    // Beaver multiplication, elementwise.
    virtual std::vector<LocalShare> multiply(std::span<const LocalShare> x,
                                             std::span<const LocalShare> y) = 0;
    // Elementwise [x <= y] for unsigned operands in [0, 2^66); result is a
    // shared bit. Operands outside the domain give undefined results.
    virtual std::vector<LocalShare> less_equal(std::span<const LocalShare> x,
                                               std::span<const LocalShare> y) = 0;
    // Elementwise [0 <= x < 2^kInputBits] as a shared bit, exact for every value
    // of the 128-bit ring, including values a dishonest input owner chose.
    virtual std::vector<LocalShare> fits_u32(std::span<const LocalShare> x) = 0;
    // Opens `match` (a shared bit) and `station_id` to both computation
    // parties. Callers must pass station_id = match * id.
    virtual AuthorizedSelection reveal_selection(const LocalShare& match,
                                                 const LocalShare& station_id) = 0;

    // ---- Local operations -------------------------------------------------
    LocalShare constant(Word value) const { return {party_id() == 0 ? value : Word{0}}; }
    static LocalShare add(LocalShare a, LocalShare b) { return {a.value + b.value}; }
    static LocalShare sub(LocalShare a, LocalShare b) { return {a.value - b.value}; }
    LocalShare not_bit(LocalShare a) const { return sub(constant(1), a); }

    // ---- Composite operations ---------------------------------------------
    std::vector<LocalShare> and_bits(std::span<const LocalShare> a,
                                     std::span<const LocalShare> b) {
        return multiply(a, b);
    }

    // Oblivious selection: condition ? when_true : when_false.
    std::vector<LocalShare> select(std::span<const LocalShare> condition,
                                   std::span<const LocalShare> when_true,
                                   std::span<const LocalShare> when_false) {
        std::vector<LocalShare> difference(condition.size());
        for (std::size_t i = 0; i < condition.size(); ++i) {
            difference[i] = sub(when_true[i], when_false[i]);
        }
        std::vector<LocalShare> result = multiply(condition, difference);
        for (std::size_t i = 0; i < result.size(); ++i) {
            result[i] = add(when_false[i], result[i]);
        }
        return result;
    }

protected:
    static void check_sizes(std::size_t a, std::size_t b) {
        if (a != b) {
            throw std::invalid_argument("secure operation operand sizes differ");
        }
    }
};

}  // namespace pps

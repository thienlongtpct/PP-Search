#pragma once

// TEST-ONLY PLAINTEXT REFERENCE EVALUATOR -- NOT SECURE, NOT MPC.
//
// Interprets LocalShare::value as the cleartext value itself so the search
// algorithm's logic (src/protocol/search.hpp) can be checked against the
// plaintext oracle over many random cases quickly. It lives in tests/ and is never linked into
// pp_party or pp_client. Security-relevant behaviour is tested with two real
// computation-party processes (tests/integration).
//
// It also records the sequence of interactive operations and their sizes, so
// tests can check that the search's control flow is independent of the data.

#include "protocol/search.hpp"

#include <stdexcept>
#include <utility>

namespace pps::testing {

class PlaintextReferenceOps final : public SecureOps {
public:
    // Honest inputs must keep every comparison operand in its documented domain,
    // and that is checked. With dishonest inputs nothing bounds the operands, so
    // comparisons instead behave as compiled: they read only the low ring bits.
    enum class Inputs { kHonest, kDishonest };
    explicit PlaintextReferenceOps(Inputs inputs = Inputs::kHonest) : inputs_(inputs) {}

    int party_id() const override { return 0; }  // constants are added once

    std::vector<LocalShare> multiply(std::span<const LocalShare> x,
                                     std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        trace_.emplace_back('*', x.size());
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            out[i].value = x[i].value * y[i].value;
        }
        return out;
    }

    std::vector<LocalShare> less_equal(std::span<const LocalShare> x,
                                       std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        trace_.emplace_back('<', x.size());
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            if (inputs_ == Inputs::kHonest) {
                check_domain(x[i].value);
                check_domain(y[i].value);
                out[i].value = x[i].value <= y[i].value ? 1 : 0;
            } else {
                // a <= b compiles to NOT [b - a < 0] on bit_length + 1 bits.
                out[i].value = (((y[i].value - x[i].value) >> kMpcBitLength) & 1) == 0 ? 1 : 0;
            }
        }
        return out;
    }

    std::vector<LocalShare> fits_u32(std::span<const LocalShare> x) override {
        trace_.emplace_back('r', x.size());
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            out[i].value = (x[i].value >> kInputBits) == 0 ? 1 : 0;
        }
        return out;
    }

    AuthorizedSelection reveal_selection(const LocalShare& match,
                                         const LocalShare& station_id) override {
        trace_.emplace_back('!', 2);
        if (match.value > 1 || (match.value == 0 && station_id.value != 0)) {
            throw std::logic_error("reveal_selection received an invalid selection");
        }
        return {match.value == 1, static_cast<std::uint64_t>(station_id.value)};
    }

    // (operation, batch size) of every interactive step, in order.
    using Trace = std::vector<std::pair<char, std::size_t>>;
    const Trace& trace() const { return trace_; }

private:
    Inputs inputs_;
    Trace trace_;

    // Enforces the documented operand bound of the secure functions.
    static void check_domain(Word value) {
        if ((value >> kComparisonOperandBits) != 0) {
            throw std::logic_error("operand outside the 66-bit comparison domain");
        }
    }
};

}  // namespace pps::testing

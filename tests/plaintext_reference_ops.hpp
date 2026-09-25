#pragma once

// TEST-ONLY PLAINTEXT REFERENCE EVALUATOR -- NOT SECURE, NOT MPC.
//
// Interprets LocalShare::value as the cleartext value itself so the search
// algorithm's logic (search.hpp) can be checked against the plaintext oracle
// over many random cases quickly. It lives in tests/ and is never linked into
// pp_party or pp_client. Security-relevant behaviour is tested with two real
// computation-party processes (tests/integration).

#include "pps/search.hpp"

#include <stdexcept>

namespace pps::testing {

class PlaintextReferenceOps final : public SecureOps {
public:
    int party_id() const override { return 0; }  // constants are added once

    std::vector<LocalShare> multiply(std::span<const LocalShare> x,
                                     std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            out[i].value = x[i].value * y[i].value;
        }
        return out;
    }

    std::vector<LocalShare> less_equal(std::span<const LocalShare> x,
                                       std::span<const LocalShare> y) override {
        check_sizes(x.size(), y.size());
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            check_domain(x[i].value);
            check_domain(y[i].value);
            out[i].value = x[i].value <= y[i].value ? 1 : 0;
        }
        return out;
    }

    std::vector<LocalShare> halve(std::span<const LocalShare> x) override {
        std::vector<LocalShare> out(x.size());
        for (std::size_t i = 0; i < x.size(); ++i) {
            check_domain(x[i].value);
            out[i].value = x[i].value >> 1;
        }
        return out;
    }

    AuthorizedSelection reveal_selection(const LocalShare& match,
                                         const LocalShare& station_id) override {
        if (match.value > 1 || (match.value == 0 && station_id.value != 0)) {
            throw std::logic_error("reveal_selection received an invalid selection");
        }
        return {match.value == 1, static_cast<std::uint64_t>(station_id.value)};
    }

private:
    // Enforces the documented operand bound of the secure functions.
    static void check_domain(Word value) {
        if ((value >> kComparisonOperandBits) != 0) {
            throw std::logic_error("operand outside the 66-bit comparison domain");
        }
    }
};

}  // namespace pps::testing

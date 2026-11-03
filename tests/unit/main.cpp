// Unit tests that need no second party: encoding, wire validation, oracle,
// cost planning, and the search logic via the test-only plaintext reference
// evaluator. Checks stay active in every build type.

#include "unit/unit_tests.hpp"

#include <iostream>

int main() {
    test_encoding();
    test_oracle();
    test_wire();
    test_cost_plan();
    test_schedule_independence();
    test_search_logic();
    test_out_of_domain_inputs();
    std::cout << "unit tests passed (search logic: plaintext reference evaluator, not MPC)\n";
}

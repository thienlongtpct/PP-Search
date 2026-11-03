#include "common/crypto.hpp"
#include "common/ring.hpp"
#include "support/check.hpp"
#include "support/plaintext_oracle.hpp"
#include "unit/unit_tests.hpp"

#include <vector>

using namespace pps;

void test_encoding() {
    CHECK(decode_signed(encode_coordinate(kCoordinateMin)) == kCoordinateMin);
    CHECK(decode_signed(encode_coordinate(kCoordinateMax)) == kCoordinateMax);
    CHECK(decode_signed(encode_coordinate(-1)) == -1);
    expect_throw<std::out_of_range>([] { encode_coordinate(kCoordinateMax + 1); }, "coordinate bound");
    expect_throw<std::out_of_range>([] { encode_radius(kRadiusMax + 1); }, "radius bound");

    std::uint8_t bytes[16];
    const Word value = (Word{0x0123456789abcdefULL} << 64) | 0xfedcba9876543210ULL;
    store_le(value, bytes);
    CHECK(bytes[0] == 0x10 && bytes[15] == 0x01);
    CHECK(load_le(bytes) == value);

    // Largest squared distance for signed 32-bit coordinates needs 65 bits.
    const Word extreme = plain_squared_distance(kCoordinateMin, kCoordinateMin,
                                                kCoordinateMax, kCoordinateMax);
    CHECK(extreme == 2 * (Word{0xffffffffULL} * 0xffffffffULL));
    CHECK((extreme >> 64) == 1);
    CHECK((extreme >> kComparisonOperandBits) == 0);

    for (int i = 0; i < 100; ++i) {
        const Word secret = random_word();
        const auto shares = share_value(secret);
        CHECK(shares[0] + shares[1] == secret);
    }
    CHECK(share_value(5)[0] != share_value(5)[0]);  // fresh randomness
}

void test_oracle() {
    const std::vector<PlainStation> stations{{10, 2, 0, 10}, {20, 1, 1, 10}};
    CHECK((plain_nearest_eligible(0, 0, stations, 100) == PlainSelection{true, 20}));
    CHECK(!plain_nearest_eligible(0, 0, {}, 100).match);
    const std::vector<PlainStation> at_horizon{{1, 5, 0, 5}};
    CHECK(plain_nearest_eligible(0, 0, at_horizon, 5).match);
    CHECK(!plain_nearest_eligible(0, 0, at_horizon, 4).match);
}

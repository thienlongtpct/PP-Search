// Unit tests that need no second party: encoding, wire validation, oracle,
// cost planning, and the search logic via the test-only plaintext reference
// evaluator. Checks stay active in every build type.

#include "check.hpp"
#include "plaintext_reference_ops.hpp"

#include "pps/oracle.hpp"
#include "pps/ring.hpp"
#include "pps/search.hpp"
#include "pps/util.hpp"
#include "pps/wire.hpp"

#include <algorithm>
#include <iostream>
#include <random>

namespace {

using namespace pps;

template <class Exception, class Function>
void expect_throw(Function function, const char* what) {
    bool thrown = false;
    try {
        function();
    } catch (const Exception&) {
        thrown = true;
    }
    if (!thrown) {
        throw std::runtime_error(std::string("expected exception: ") + what);
    }
}

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

void test_wire() {
    wire::Frame frame;
    frame.type = wire::MsgType::kInputShare;
    frame.step = wire::Step::kInput;
    frame.session = random_session_id();
    frame.sequence = 9;
    frame.payload = wire::encode(wire::InputShare{wire::OwnerKind::kStation, wire::Field::kY, 42, 7});
    auto header = wire::encode_header(frame);
    const wire::Header decoded = wire::decode_header(header.data());
    CHECK(decoded.type == frame.type && decoded.sequence == 9 && decoded.session == frame.session);
    CHECK(decoded.payload_length == frame.payload.size());

    auto corrupt = header;
    corrupt[0] ^= 1;
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "bad magic");
    corrupt = header;
    corrupt[4] = 2;
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "bad version");
    corrupt = header;
    corrupt[24] = static_cast<std::uint8_t>(wire::Step::kOutput);
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "step mismatch");
    corrupt = header;
    corrupt[35] = 0xff;  // payload length far above the bound
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "oversize");
    corrupt = header;
    corrupt[39] = 1;
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "reserved");
    corrupt = header;
    corrupt[6] = 99;
    expect_throw<ProtocolError>([&] { wire::decode_header(corrupt.data()); }, "unknown type");

    const wire::InputShare share = wire::decode_input_share(frame.payload);
    CHECK(share.station_id == 42 && share.share == 7 && share.field == wire::Field::kY);
    auto trailing = frame.payload;
    trailing.push_back(0);
    expect_throw<ProtocolError>([&] { wire::decode_input_share(trailing); }, "trailing bytes");
    auto truncated = frame.payload;
    truncated.pop_back();
    expect_throw<ProtocolError>([&] { wire::decode_input_share(truncated); }, "truncated");
    expect_throw<ProtocolError>(
        [] {
            wire::decode_input_share(wire::encode(
                wire::InputShare{wire::OwnerKind::kRequester, wire::Field::kRadius, 0, 1}));
        },
        "requester radius");

    wire::SessionOpen open;
    open.horizon = 100;
    open.mode = wire::Mode::kDirectArgmin;
    open.timeout_ms = 1000;
    open.requester = "alice";
    open.station_ids = {1, 5, 9};
    const wire::SessionOpen round_trip = wire::decode_session_open(wire::encode(open));
    CHECK(round_trip.station_ids == open.station_ids && round_trip.requester == "alice");
    CHECK(round_trip.mode == wire::Mode::kDirectArgmin);
    open.station_ids = {1, 5, 5};
    try {
        wire::decode_session_open(wire::encode(open));
        CHECK(false);
    } catch (const ProtocolError& error) {
        CHECK(error.code() == AbortCode::kDuplicate);
    }
    open.station_ids = {5, 1};
    expect_throw<ProtocolError>([&] { wire::decode_session_open(wire::encode(open)); }, "unsorted");
    open.station_ids = {};
    open.requester = "bad name";
    expect_throw<ProtocolError>([&] { wire::decode_session_open(wire::encode(open)); }, "requester");

    expect_throw<ProtocolError>(
        [] { wire::decode_session_result(wire::encode(wire::SessionResult{false, 3})); },
        "no-match with ID");
    const wire::Abort abort = wire::decode_abort(wire::encode(wire::Abort{AbortCode::kTimeout, "late"}));
    CHECK(abort.code == AbortCode::kTimeout && abort.message == "late");

    const wire::SessionId session = random_session_id();
    CHECK(wire::parse_session_hex(wire::session_hex(session)) == session);
    CHECK(wire::station_identity(12) == "station:12");
}

void test_cost_plan() {
    CHECK(binary_search_rounds(0) == 1);
    CHECK(binary_search_rounds(1) == 2);
    CHECK(binary_search_rounds(1'000'000) == 20);
    CHECK(binary_search_rounds(0xffffffffu) == 33);
    for (const std::size_t n : {1u, 2u, 7u, 64u}) {
        const OperationCounts argmin = plan_search(n, 1000, SearchMode::kDirectArgmin);
        CHECK(argmin.multiplications == 3 * n + n + 5 * (n - 1) + 1);
        CHECK(argmin.comparisons == 2 * n + (n - 1));
        CHECK(argmin.halvings == 0);
        const std::uint64_t rounds = binary_search_rounds(1000);
        const OperationCounts binary = plan_search(n, 1000, SearchMode::kBinaryThenExact);
        CHECK(binary.multiplications ==
              argmin.multiplications + rounds * (1 + n + (n - 1) + 2 + 2) + 1 + n);
        CHECK(binary.comparisons == argmin.comparisons + rounds * (n + 1) + n);
        CHECK(binary.halvings == rounds);
    }
    CHECK(plan_search(0, 10, SearchMode::kBinaryThenExact).multiplications == 0);
}

PlainSelection run_reference(std::int32_t ax, std::int32_t ay, std::vector<PlainStation> stations,
                             std::uint32_t horizon, SearchMode mode) {
    std::sort(stations.begin(), stations.end(),
              [](const PlainStation& a, const PlainStation& b) { return a.id < b.id; });
    testing::PlaintextReferenceOps ops;
    std::vector<StationShares> shares;
    for (const PlainStation& s : stations) {
        shares.push_back({s.id, {encode_coordinate(s.x)}, {encode_coordinate(s.y)},
                          {encode_radius(s.support_radius)}});
    }
    const AuthorizedSelection result = nearest_eligible_station(
        ops, {{encode_coordinate(ax)}, {encode_coordinate(ay)}}, shares, horizon, mode);
    return {result.match, result.station_id};
}

void check_both_modes(std::int32_t ax, std::int32_t ay, const std::vector<PlainStation>& stations,
                      std::uint32_t horizon) {
    const PlainSelection expected = plain_nearest_eligible(ax, ay, stations, horizon);
    for (const SearchMode mode : {SearchMode::kBinaryThenExact, SearchMode::kDirectArgmin}) {
        const PlainSelection actual = run_reference(ax, ay, stations, horizon, mode);
        if (!(actual == expected)) {
            throw std::runtime_error("search logic disagrees with the plaintext oracle");
        }
    }
}

void test_search_logic() {
    check_both_modes(0, 0, {{10, 2, 0, 10}, {20, 1, 1, 10}}, 100);
    check_both_modes(0, 0, {{1, 100, 0, 100}}, 100);              // exactly at D
    check_both_modes(0, 0, {{1, 101, 0, 1000}}, 100);             // D + 1
    check_both_modes(0, 0, {{1, 1, 0, 0}, {2, 5, 0, 10}}, 100);   // closer but radius too small
    check_both_modes(0, 0, {{9, 3, 4, 5}, {4, -3, -4, 5}}, 10);   // tie -> smaller ID
    check_both_modes(0, 0, {{4, -3, -4, 5}, {9, 3, 4, 5}}, 10);   // reversed insertion order
    check_both_modes(0, 0, {}, 10);
    check_both_modes(0, 0, {{1, 5, 5, 1}, {2, 6, 6, 2}}, 100);    // all ineligible
    check_both_modes(7, 7, {{3, 7, 7, 0}}, 0);                    // zero distance, zero radius
    check_both_modes(kCoordinateMin, kCoordinateMin,
                     {{1, static_cast<std::int32_t>(kCoordinateMax), static_cast<std::int32_t>(kCoordinateMax),
                       static_cast<std::uint32_t>(kRadiusMax)}},
                     0xffffffffu);                                 // extreme: q ~ 2^65 > D^2
    check_both_modes(kCoordinateMin, 0,
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
        check_both_modes(coordinate(), coordinate(), stations, horizon);
    }
}

}  // namespace

int main() {
    test_encoding();
    test_oracle();
    test_wire();
    test_cost_plan();
    test_search_logic();
    std::cout << "unit tests passed (search logic: plaintext reference evaluator, not MPC)\n";
}

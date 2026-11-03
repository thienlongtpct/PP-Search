#include "net/wire.hpp"
#include "support/check.hpp"
#include "unit/unit_tests.hpp"

using namespace pps;

void test_wire() {
    wire::Frame frame;
    frame.type = wire::MsgType::kInputShare;
    frame.step = wire::Step::kInput;
    frame.session = wire::random_session_id();
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
    open.timeout_ms = 1000;
    open.requester = "alice";
    open.station_ids = {1, 5, 9};
    const wire::SessionOpen round_trip = wire::decode_session_open(wire::encode(open));
    CHECK(round_trip.station_ids == open.station_ids && round_trip.requester == "alice");
    CHECK(round_trip.mode == wire::Mode::kDirectSelection);
    open.mode = static_cast<wire::Mode>(1);  // not a search mode
    expect_throw<ProtocolError>([&] { wire::decode_session_open(wire::encode(open)); }, "mode");
    open.mode = wire::Mode::kDirectSelection;
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

    const wire::SessionId session = wire::random_session_id();
    CHECK(wire::parse_session_hex(wire::session_hex(session)) == session);
    CHECK(wire::station_identity(12) == "station:12");
}

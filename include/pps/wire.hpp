#pragma once

// Message framing and payload formats for every non-MPC channel:
// coordinator <-> party, input owner -> party, party -> output recipient,
// and the party0 <-> party1 control channel. MPC traffic between the parties
// uses MP-SPDZ's own TLS channel instead (see docs/ARCHITECTURE.md).
//
// Frame = 40-byte header || payload, all integers little-endian.
//   magic u32 | version u16 | type u16 | session_id [16] | step u32 |
//   sequence u32 | payload_length u32 | reserved u32 (= 0)

#include "pps/errors.hpp"
#include "pps/ring.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pps::wire {

inline constexpr std::uint32_t kMagic = 0x31535050;  // bytes "PPS1"
inline constexpr std::uint16_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 40;
inline constexpr std::uint32_t kMaxPayload = 1u << 20;
inline constexpr std::uint32_t kMaxStations = 65536;
inline constexpr std::size_t kMaxRequesterName = 64;
inline constexpr std::size_t kMaxAbortMessage = 256;

using SessionId = std::array<std::uint8_t, 16>;

enum class MsgType : std::uint16_t {
    kSessionOpen = 1,    // coordinator -> party
    kSessionResult = 2,  // party -> coordinator
    kInputShare = 3,     // input owner -> party
    kInputDone = 4,      // input owner -> party
    kInputAck = 5,       // party -> input owner
    kOutputShare = 6,    // party -> selected station
    kNoOutput = 7,       // party -> non-selected station
    kAbort = 8,          // any direction
    kPeerSync = 9,       // party <-> party control channel
};

// Protocol step carried in every header; each message type is only valid in
// its designated step.
enum class Step : std::uint32_t {
    kSetup = 1,
    kInput = 2,
    kCompute = 3,
    kOutput = 4,
    kAbort = 5,
};

enum class OwnerKind : std::uint8_t { kRequester = 1, kStation = 2 };
enum class Field : std::uint8_t { kX = 1, kY = 2, kRadius = 3 };
enum class Mode : std::uint8_t { kBinaryThenExact = 1, kDirectArgmin = 2 };

struct Frame {
    MsgType type{};
    Step step{};
    SessionId session{};
    std::uint32_t sequence = 0;  // assigned by the transport on send
    std::vector<std::uint8_t> payload;
};

struct Header {
    MsgType type;
    Step step;
    SessionId session;
    std::uint32_t sequence;
    std::uint32_t payload_length;
};

Step step_for(MsgType type);
std::array<std::uint8_t, kHeaderSize> encode_header(const Frame& frame);
// Validates magic, version, reserved field, type, step and length bound.
Header decode_header(const std::uint8_t* bytes);

struct SessionOpen {
    std::uint32_t horizon = 0;
    Mode mode = Mode::kBinaryThenExact;
    std::uint32_t timeout_ms = 0;
    std::string requester;                 // authorised requester name
    std::vector<std::uint64_t> station_ids;  // strictly increasing
};

struct InputShare {
    OwnerKind owner{};
    Field field{};
    std::uint64_t station_id = 0;  // 0 and unused for the requester
    Word share = 0;
};

struct InputDone {
    OwnerKind owner{};
    std::uint64_t station_id = 0;
    std::uint32_t field_count = 0;
    // Random per-submission identifier. Both parties include it in their
    // input-set digest, so shares from two different sharings of the same
    // owner (e.g. racing duplicate submissions) abort the session instead of
    // silently reconstructing an inconsistent value.
    std::array<std::uint8_t, 16> submission_id{};
};

struct SessionResult {
    bool match = false;
    std::uint64_t station_id = 0;
};

struct OutputShare {
    std::uint64_t station_id = 0;
    Field field{};
    Word share = 0;
};

struct NoOutput {
    std::uint64_t station_id = 0;
};

struct Abort {
    AbortCode code = AbortCode::kInternal;
    std::string message;
};

struct PeerSync {
    std::uint32_t phase = 0;
    std::uint8_t status = 0;  // 0 = ok, otherwise an AbortCode value
    std::array<std::uint8_t, 32> digest{};
};

std::vector<std::uint8_t> encode(const SessionOpen& value);
std::vector<std::uint8_t> encode(const InputShare& value);
std::vector<std::uint8_t> encode(const InputDone& value);
std::vector<std::uint8_t> encode(const SessionResult& value);
std::vector<std::uint8_t> encode(const OutputShare& value);
std::vector<std::uint8_t> encode(const NoOutput& value);
std::vector<std::uint8_t> encode(const Abort& value);
std::vector<std::uint8_t> encode(const PeerSync& value);

// Decoders reject trailing bytes, out-of-range enums and invalid contents.
SessionOpen decode_session_open(const std::vector<std::uint8_t>& payload);
InputShare decode_input_share(const std::vector<std::uint8_t>& payload);
InputDone decode_input_done(const std::vector<std::uint8_t>& payload);
SessionResult decode_session_result(const std::vector<std::uint8_t>& payload);
OutputShare decode_output_share(const std::vector<std::uint8_t>& payload);
NoOutput decode_no_output(const std::vector<std::uint8_t>& payload);
Abort decode_abort(const std::vector<std::uint8_t>& payload);
PeerSync decode_peer_sync(const std::vector<std::uint8_t>& payload);

template <class Payload>
Frame make_frame(MsgType type, const SessionId& session, const Payload& payload) {
    Frame frame;
    frame.type = type;
    frame.step = step_for(type);
    frame.session = session;
    frame.payload = encode(payload);
    return frame;
}

std::string session_hex(const SessionId& session);
SessionId parse_session_hex(const std::string& text);
bool valid_requester_name(const std::string& name);

// Certificate common names that identify each role.
std::string requester_identity(const std::string& name);
std::string station_identity(std::uint64_t station_id);
inline constexpr const char* kCoordinatorIdentity = "coordinator";
std::string party_identity(int party_id);

}  // namespace pps::wire

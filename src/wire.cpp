#include "pps/wire.hpp"

#include <algorithm>
#include <cctype>

namespace pps::wire {
namespace {

class Writer {
public:
    void u8(std::uint8_t value) { bytes_.push_back(value); }
    void u16(std::uint16_t value) { put(value, 2); }
    void u32(std::uint32_t value) { put(value, 4); }
    void u64(std::uint64_t value) { put(value, 8); }
    void word(Word value) {
        std::uint8_t buffer[16];
        store_le(value, buffer);
        bytes_.insert(bytes_.end(), buffer, buffer + 16);
    }
    void raw(const std::uint8_t* data, std::size_t size) {
        bytes_.insert(bytes_.end(), data, data + size);
    }
    void string16(const std::string& text) {
        u16(static_cast<std::uint16_t>(text.size()));
        raw(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }
    std::vector<std::uint8_t> take() { return std::move(bytes_); }

private:
    void put(std::uint64_t value, int size) {
        for (int i = 0; i < size; ++i) {
            bytes_.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
        }
    }
    std::vector<std::uint8_t> bytes_;
};

class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}
    explicit Reader(const std::vector<std::uint8_t>& bytes)
        : Reader(bytes.data(), bytes.size()) {}

    std::uint8_t u8() { return static_cast<std::uint8_t>(get(1)); }
    std::uint16_t u16() { return static_cast<std::uint16_t>(get(2)); }
    std::uint32_t u32() { return static_cast<std::uint32_t>(get(4)); }
    std::uint64_t u64() { return get(8); }
    Word word() {
        need(16);
        const Word value = load_le(data_ + offset_);
        offset_ += 16;
        return value;
    }
    void raw(std::uint8_t* out, std::size_t size) {
        need(size);
        std::copy_n(data_ + offset_, size, out);
        offset_ += size;
    }
    std::string string16(std::size_t max_length) {
        const std::size_t length = u16();
        if (length > max_length) {
            throw ProtocolError("string field exceeds its bound");
        }
        need(length);
        std::string text(reinterpret_cast<const char*>(data_ + offset_), length);
        offset_ += length;
        return text;
    }
    std::size_t remaining() const { return size_ - offset_; }
    void finish() const {
        if (offset_ != size_) {
            throw ProtocolError("trailing bytes in payload");
        }
    }

private:
    void need(std::size_t count) const {
        if (count > size_ - offset_) {
            throw ProtocolError("truncated payload");
        }
    }
    std::uint64_t get(int size) {
        need(static_cast<std::size_t>(size));
        std::uint64_t value = 0;
        for (int i = size - 1; i >= 0; --i) {
            value = (value << 8) | data_[offset_ + static_cast<std::size_t>(i)];
        }
        offset_ += static_cast<std::size_t>(size);
        return value;
    }

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
};

MsgType checked_type(std::uint16_t value) {
    if (value < static_cast<std::uint16_t>(MsgType::kSessionOpen) ||
        value > static_cast<std::uint16_t>(MsgType::kPeerSync)) {
        throw ProtocolError("unknown message type");
    }
    return static_cast<MsgType>(value);
}

Field checked_field(std::uint8_t value) {
    if (value < 1 || value > 3) {
        throw ProtocolError("unknown input field");
    }
    return static_cast<Field>(value);
}

OwnerKind checked_owner(std::uint8_t value) {
    if (value != 1 && value != 2) {
        throw ProtocolError("unknown input owner kind");
    }
    return static_cast<OwnerKind>(value);
}

void expect_zero(std::uint32_t value, const char* what) {
    if (value != 0) {
        throw ProtocolError(std::string("nonzero reserved field: ") + what);
    }
}

bool printable(const std::string& text) {
    return std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return c >= 0x20 && c < 0x7f;
    });
}

}  // namespace

Step step_for(MsgType type) {
    switch (type) {
    case MsgType::kSessionOpen: return Step::kSetup;
    case MsgType::kPeerSync: return Step::kSetup;
    case MsgType::kInputShare:
    case MsgType::kInputDone:
    case MsgType::kInputAck: return Step::kInput;
    case MsgType::kSessionResult:
    case MsgType::kOutputShare:
    case MsgType::kNoOutput: return Step::kOutput;
    case MsgType::kAbort: return Step::kAbort;
    }
    throw ProtocolError("unknown message type");
}

std::array<std::uint8_t, kHeaderSize> encode_header(const Frame& frame) {
    if (frame.payload.size() > kMaxPayload) {
        throw ProtocolError("payload exceeds maximum frame size");
    }
    Writer writer;
    writer.u32(kMagic);
    writer.u16(kVersion);
    writer.u16(static_cast<std::uint16_t>(frame.type));
    writer.raw(frame.session.data(), frame.session.size());
    writer.u32(static_cast<std::uint32_t>(frame.step));
    writer.u32(frame.sequence);
    writer.u32(static_cast<std::uint32_t>(frame.payload.size()));
    writer.u32(0);
    const std::vector<std::uint8_t> bytes = writer.take();
    std::array<std::uint8_t, kHeaderSize> header{};
    std::copy(bytes.begin(), bytes.end(), header.begin());
    return header;
}

Header decode_header(const std::uint8_t* bytes) {
    Reader reader(bytes, kHeaderSize);
    if (reader.u32() != kMagic) {
        throw ProtocolError("bad frame magic");
    }
    if (reader.u16() != kVersion) {
        throw ProtocolError("unsupported protocol version");
    }
    Header header{};
    header.type = checked_type(reader.u16());
    reader.raw(header.session.data(), header.session.size());
    const std::uint32_t step = reader.u32();
    if (step != static_cast<std::uint32_t>(step_for(header.type))) {
        throw ProtocolError("message type not valid in this protocol step");
    }
    header.step = static_cast<Step>(step);
    header.sequence = reader.u32();
    header.payload_length = reader.u32();
    if (header.payload_length > kMaxPayload) {
        throw ProtocolError("frame length exceeds bound");
    }
    expect_zero(reader.u32(), "header");
    reader.finish();
    return header;
}

std::vector<std::uint8_t> encode(const SessionOpen& value) {
    Writer writer;
    writer.u32(value.horizon);
    writer.u8(static_cast<std::uint8_t>(value.mode));
    writer.u8(0);
    writer.u16(0);
    writer.u32(value.timeout_ms);
    writer.string16(value.requester);
    writer.u32(static_cast<std::uint32_t>(value.station_ids.size()));
    for (const std::uint64_t id : value.station_ids) {
        writer.u64(id);
    }
    return writer.take();
}

SessionOpen decode_session_open(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    SessionOpen value;
    value.horizon = reader.u32();
    const std::uint8_t mode = reader.u8();
    if (mode != 1 && mode != 2) {
        throw ProtocolError("unknown search mode");
    }
    value.mode = static_cast<Mode>(mode);
    expect_zero(reader.u8(), "session-open padding");
    expect_zero(reader.u16(), "session-open padding");
    value.timeout_ms = reader.u32();
    if (value.timeout_ms == 0) {
        throw ProtocolError("session timeout must be positive");
    }
    value.requester = reader.string16(kMaxRequesterName);
    if (!valid_requester_name(value.requester)) {
        throw ProtocolError(AbortCode::kUnauthorized, "invalid requester name");
    }
    const std::uint32_t count = reader.u32();
    if (count > kMaxStations) {
        throw ProtocolError("too many stations");
    }
    if (reader.remaining() != std::size_t{count} * 8) {
        throw ProtocolError("station list length mismatch");
    }
    value.station_ids.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint64_t id = reader.u64();
        if (!value.station_ids.empty() && id <= value.station_ids.back()) {
            throw ProtocolError(AbortCode::kDuplicate,
                                id == value.station_ids.back()
                                    ? "duplicate station ID"
                                    : "station IDs not in ascending order");
        }
        value.station_ids.push_back(id);
    }
    reader.finish();
    return value;
}

std::vector<std::uint8_t> encode(const InputShare& value) {
    Writer writer;
    writer.u8(static_cast<std::uint8_t>(value.owner));
    writer.u8(static_cast<std::uint8_t>(value.field));
    writer.u16(0);
    writer.u64(value.station_id);
    writer.word(value.share);
    return writer.take();
}

InputShare decode_input_share(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    InputShare value;
    value.owner = checked_owner(reader.u8());
    value.field = checked_field(reader.u8());
    expect_zero(reader.u16(), "input-share padding");
    value.station_id = reader.u64();
    value.share = reader.word();
    reader.finish();
    if (value.owner == OwnerKind::kRequester) {
        if (value.field == Field::kRadius || value.station_id != 0) {
            throw ProtocolError("invalid requester input field");
        }
    }
    return value;
}

std::vector<std::uint8_t> encode(const InputDone& value) {
    Writer writer;
    writer.u8(static_cast<std::uint8_t>(value.owner));
    writer.u8(0);
    writer.u16(0);
    writer.u64(value.station_id);
    writer.u32(value.field_count);
    writer.raw(value.submission_id.data(), value.submission_id.size());
    return writer.take();
}

InputDone decode_input_done(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    InputDone value;
    value.owner = checked_owner(reader.u8());
    expect_zero(reader.u8(), "input-done padding");
    expect_zero(reader.u16(), "input-done padding");
    value.station_id = reader.u64();
    value.field_count = reader.u32();
    reader.raw(value.submission_id.data(), value.submission_id.size());
    reader.finish();
    return value;
}

std::vector<std::uint8_t> encode(const SessionResult& value) {
    Writer writer;
    writer.u8(value.match ? 1 : 0);
    writer.u8(0);
    writer.u16(0);
    writer.u64(value.station_id);
    return writer.take();
}

SessionResult decode_session_result(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    SessionResult value;
    const std::uint8_t match = reader.u8();
    if (match > 1) {
        throw ProtocolError("invalid match flag");
    }
    value.match = match == 1;
    expect_zero(reader.u8(), "result padding");
    expect_zero(reader.u16(), "result padding");
    value.station_id = reader.u64();
    reader.finish();
    if (!value.match && value.station_id != 0) {
        throw ProtocolError("no-match result carries a station ID");
    }
    return value;
}

std::vector<std::uint8_t> encode(const OutputShare& value) {
    Writer writer;
    writer.u64(value.station_id);
    writer.u8(static_cast<std::uint8_t>(value.field));
    writer.u8(0);
    writer.u16(0);
    writer.word(value.share);
    return writer.take();
}

OutputShare decode_output_share(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    OutputShare value;
    value.station_id = reader.u64();
    value.field = checked_field(reader.u8());
    if (value.field == Field::kRadius) {
        throw ProtocolError("radius is never an output field");
    }
    expect_zero(reader.u8(), "output padding");
    expect_zero(reader.u16(), "output padding");
    value.share = reader.word();
    reader.finish();
    return value;
}

std::vector<std::uint8_t> encode(const NoOutput& value) {
    Writer writer;
    writer.u64(value.station_id);
    return writer.take();
}

NoOutput decode_no_output(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    NoOutput value;
    value.station_id = reader.u64();
    reader.finish();
    return value;
}

std::vector<std::uint8_t> encode(const Abort& value) {
    Writer writer;
    writer.u32(static_cast<std::uint32_t>(value.code));
    std::string message = value.message.substr(0, kMaxAbortMessage);
    for (char& c : message) {
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) >= 0x7f) {
            c = '?';
        }
    }
    writer.string16(message);
    return writer.take();
}

Abort decode_abort(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    Abort value;
    const std::uint32_t code = reader.u32();
    if (code < 1 || code > static_cast<std::uint32_t>(AbortCode::kSessionClosed)) {
        throw ProtocolError("unknown abort code");
    }
    value.code = static_cast<AbortCode>(code);
    value.message = reader.string16(kMaxAbortMessage);
    if (!printable(value.message)) {
        throw ProtocolError("non-printable abort message");
    }
    reader.finish();
    return value;
}

std::vector<std::uint8_t> encode(const PeerSync& value) {
    Writer writer;
    writer.u32(value.phase);
    writer.u8(value.status);
    writer.u8(0);
    writer.u16(0);
    writer.raw(value.digest.data(), value.digest.size());
    return writer.take();
}

PeerSync decode_peer_sync(const std::vector<std::uint8_t>& payload) {
    Reader reader(payload);
    PeerSync value;
    value.phase = reader.u32();
    value.status = reader.u8();
    expect_zero(reader.u8(), "peer-sync padding");
    expect_zero(reader.u16(), "peer-sync padding");
    reader.raw(value.digest.data(), value.digest.size());
    reader.finish();
    return value;
}

std::string session_hex(const SessionId& session) {
    static const char* digits = "0123456789abcdef";
    std::string text;
    for (const std::uint8_t byte : session) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}

SessionId parse_session_hex(const std::string& text) {
    if (text.size() != 32) {
        throw std::invalid_argument("session ID must be 32 hex digits");
    }
    SessionId session{};
    for (std::size_t i = 0; i < 16; ++i) {
        const auto nibble = [&](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::invalid_argument("session ID must be hexadecimal");
        };
        session[i] = static_cast<std::uint8_t>(nibble(text[2 * i]) * 16 + nibble(text[2 * i + 1]));
    }
    return session;
}

bool valid_requester_name(const std::string& name) {
    return !name.empty() && name.size() <= kMaxRequesterName &&
           std::all_of(name.begin(), name.end(), [](unsigned char c) {
               return std::isalnum(c) || c == '-' || c == '_' || c == '.';
           });
}

std::string requester_identity(const std::string& name) { return "requester:" + name; }
std::string station_identity(std::uint64_t station_id) {
    return "station:" + std::to_string(station_id);
}
std::string party_identity(int party_id) { return "party" + std::to_string(party_id); }

}  // namespace pps::wire

#include "pps/util.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <iomanip>

namespace pps {

void random_bytes(std::uint8_t* out, std::size_t size) {
    if (size > static_cast<std::size_t>(INT32_MAX) ||
        RAND_bytes(out, static_cast<int>(size)) != 1) {
        throw std::runtime_error("CSPRNG failure");
    }
}

Word random_word() {
    std::uint8_t bytes[16];
    random_bytes(bytes, sizeof bytes);
    return load_le(bytes);
}

wire::SessionId random_session_id() {
    wire::SessionId session{};
    random_bytes(session.data(), session.size());
    return session;
}

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    std::array<std::uint8_t, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != digest.size()) {
        throw std::runtime_error("SHA-256 failure");
    }
    return digest;
}

Arguments::Arguments(int argc, char** argv, int first) {
    for (int i = first; i < argc; ++i) {
        const std::string name(argv[i]);
        if (name.rfind("--", 0) != 0 || name.size() < 3) {
            throw std::invalid_argument("unexpected argument: " + name);
        }
        if (i + 1 >= argc) {
            throw std::invalid_argument("missing value for " + name);
        }
        if (!values_.emplace(name.substr(2), argv[++i]).second) {
            throw std::invalid_argument("repeated option " + name);
        }
    }
}

std::string Arguments::get(const std::string& name) const {
    const auto it = values_.find(name);
    if (it == values_.end()) {
        throw std::invalid_argument("missing required option --" + name);
    }
    return it->second;
}

std::string Arguments::get(const std::string& name, const std::string& fallback) const {
    const auto it = values_.find(name);
    return it == values_.end() ? fallback : it->second;
}

std::int64_t Arguments::get_int(const std::string& name) const { return parse_i64(get(name)); }
std::int64_t Arguments::get_int(const std::string& name, std::int64_t fallback) const {
    return has(name) ? parse_i64(get(name)) : fallback;
}
std::uint64_t Arguments::get_uint(const std::string& name) const { return parse_u64(get(name)); }
std::uint64_t Arguments::get_uint(const std::string& name, std::uint64_t fallback) const {
    return has(name) ? parse_u64(get(name)) : fallback;
}

void Arguments::allow_only(const std::vector<std::string>& known) const {
    for (const auto& [name, value] : values_) {
        if (std::find(known.begin(), known.end(), name) == known.end()) {
            throw std::invalid_argument("unknown option --" + name);
        }
    }
}

std::uint64_t parse_u64(const std::string& text) {
    if (text.empty() || !std::all_of(text.begin(), text.end(), ::isdigit)) {
        throw std::invalid_argument("expected an unsigned integer: '" + text + "'");
    }
    std::size_t used = 0;
    const unsigned long long value = std::stoull(text, &used, 10);
    return value;
}

std::int64_t parse_i64(const std::string& text) {
    const bool negative = !text.empty() && text[0] == '-';
    const std::uint64_t magnitude = parse_u64(negative ? text.substr(1) : text);
    if (negative) {
        if (magnitude > std::uint64_t{1} << 63) {
            throw std::out_of_range("integer out of range: " + text);
        }
        return static_cast<std::int64_t>(0 - magnitude);
    }
    if (magnitude > static_cast<std::uint64_t>(INT64_MAX)) {
        throw std::out_of_range("integer out of range: " + text);
    }
    return static_cast<std::int64_t>(magnitude);
}

std::string json_escape(const std::string& text) {
    std::ostringstream out;
    for (const unsigned char c : text) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << int(c)
                    << std::dec;
            } else {
                out << c;
            }
        }
    }
    return out.str();
}

void JsonObject::key(const std::string& name) {
    if (!first_) {
        body_ << ',';
    }
    first_ = false;
    body_ << '"' << json_escape(name) << "\":";
}

JsonObject& JsonObject::add(const std::string& name, const std::string& value) {
    key(name);
    body_ << '"' << json_escape(value) << '"';
    return *this;
}

JsonObject& JsonObject::add(const std::string& name, bool value) {
    key(name);
    body_ << (value ? "true" : "false");
    return *this;
}

JsonObject& JsonObject::add(const std::string& name, double value) {
    key(name);
    if (std::isfinite(value)) {
        body_ << std::setprecision(9) << value;
    } else {
        body_ << "null";
    }
    return *this;
}

JsonObject& JsonObject::add(const std::string& name, std::int64_t value) {
    key(name);
    body_ << value;
    return *this;
}

JsonObject& JsonObject::add(const std::string& name, std::uint64_t value) {
    key(name);
    body_ << value;
    return *this;
}

JsonObject& JsonObject::add_raw(const std::string& name, const std::string& json) {
    key(name);
    body_ << json;
    return *this;
}

PkiFiles pki_files(const std::string& directory, const std::string& identity) {
    std::string stem = identity;
    std::replace(stem.begin(), stem.end(), ':', '-');
    return {directory + "/ca.pem", directory + "/" + stem + ".pem", directory + "/" + stem + ".key"};
}

}  // namespace pps

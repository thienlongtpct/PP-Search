#pragma once

#include "pps/ring.hpp"
#include "pps/wire.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace pps {

// Fresh randomness from OpenSSL's CSPRNG (RAND_bytes). Throws on failure.
void random_bytes(std::uint8_t* out, std::size_t size);
Word random_word();
wire::SessionId random_session_id();

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data);

// Splits `value` into two uniformly random additive shares modulo 2^128.
inline std::array<Word, 2> share_value(Word value) {
    const Word mask = random_word();
    return {mask, value - mask};
}

// Minimal "--name value" argument parser. Flags without values are not used.
class Arguments {
public:
    Arguments(int argc, char** argv, int first);
    bool has(const std::string& name) const { return values_.count(name) != 0; }
    std::string get(const std::string& name) const;
    std::string get(const std::string& name, const std::string& fallback) const;
    std::int64_t get_int(const std::string& name) const;
    std::int64_t get_int(const std::string& name, std::int64_t fallback) const;
    std::uint64_t get_uint(const std::string& name) const;
    std::uint64_t get_uint(const std::string& name, std::uint64_t fallback) const;
    // Fails on any option not in `known`.
    void allow_only(const std::vector<std::string>& known) const;

private:
    std::map<std::string, std::string> values_;
};

// Tiny JSON object writer (flat values and nested raw JSON).
class JsonObject {
public:
    JsonObject& add(const std::string& key, const std::string& value);
    JsonObject& add(const std::string& key, const char* value) { return add(key, std::string(value)); }
    JsonObject& add(const std::string& key, bool value);
    JsonObject& add(const std::string& key, double value);
    JsonObject& add(const std::string& key, std::int64_t value);
    JsonObject& add(const std::string& key, std::uint64_t value);
    JsonObject& add(const std::string& key, int value) { return add(key, static_cast<std::int64_t>(value)); }
    JsonObject& add(const std::string& key, unsigned value) { return add(key, static_cast<std::uint64_t>(value)); }
    JsonObject& add_raw(const std::string& key, const std::string& json);
    std::string str() const { return "{" + body_.str() + "}"; }

private:
    void key(const std::string& name);
    std::ostringstream body_;
    bool first_ = true;
};

std::string json_escape(const std::string& text);

// PKI file layout: <dir>/ca.pem and <dir>/<stem>.pem / <stem>.key, where the
// stem is the identity with ':' replaced by '-'.
struct PkiFiles {
    std::string ca;
    std::string certificate;
    std::string key;
};
PkiFiles pki_files(const std::string& directory, const std::string& identity);

std::uint64_t parse_u64(const std::string& text);
std::int64_t parse_i64(const std::string& text);

}  // namespace pps

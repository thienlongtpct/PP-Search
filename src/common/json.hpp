#pragma once

#include <cstdint>
#include <sstream>
#include <string>

namespace pps {

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

}  // namespace pps

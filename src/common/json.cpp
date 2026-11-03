#include "common/json.hpp"

#include <cmath>
#include <iomanip>

namespace pps {

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

}  // namespace pps

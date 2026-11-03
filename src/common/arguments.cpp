#include "common/arguments.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <stdexcept>

namespace pps {

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

}  // namespace pps

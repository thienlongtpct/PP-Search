#pragma once

// Command-line and integer parsing shared by pp_party and pp_client.

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace pps {

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

std::uint64_t parse_u64(const std::string& text);
std::int64_t parse_i64(const std::string& text);

}  // namespace pps

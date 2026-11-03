#pragma once

// Randomness, hashing and additive secret sharing, all backed by OpenSSL.

#include "common/ring.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace pps {

// Fresh randomness from OpenSSL's CSPRNG (RAND_bytes). Throws on failure.
void random_bytes(std::uint8_t* out, std::size_t size);
Word random_word();

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data);

// Splits `value` into two uniformly random additive shares modulo 2^128.
inline std::array<Word, 2> share_value(Word value) {
    const Word mask = random_word();
    return {mask, value - mask};
}

}  // namespace pps

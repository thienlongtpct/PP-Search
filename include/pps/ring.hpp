#pragma once

// Arithmetic domain and input encoding shared by every component.
//
// All secret values are additively shared over the ring Z_(2^128), which is
// the domain of MP-SPDZ's semi2k protocol instantiated as Semi2kShare<128>.
// Coordinates are signed 32-bit Cartesian integers (for example metres in a
// local projected frame, never raw latitude/longitude) encoded in two's
// complement modulo 2^128. See docs/ARCHITECTURE.md for the bound analysis.

#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace pps {

__extension__ typedef unsigned __int128 Word;
__extension__ typedef __int128 SignedWord;

inline constexpr int kRingBits = 128;

// Encoded input domains.
inline constexpr std::int64_t kCoordinateMin = std::numeric_limits<std::int32_t>::min();
inline constexpr std::int64_t kCoordinateMax = std::numeric_limits<std::int32_t>::max();
inline constexpr std::uint64_t kRadiusMax = std::numeric_limits<std::uint32_t>::max();
inline constexpr std::uint64_t kHorizonMax = std::numeric_limits<std::uint32_t>::max();

// Every secure comparison and halving operand is an unsigned integer strictly
// below 2^kComparisonOperandBits. The MP-SPDZ functions are compiled with a
// signed bit length of kComparisonOperandBits + 1 (see mpc/pp_ops.py), which
// keeps the difference of two operands inside the comparison domain.
inline constexpr int kComparisonOperandBits = 66;
inline constexpr int kMpcBitLength = kComparisonOperandBits + 1;

// Largest values that occur in the search (all well below 2^66):
//   dx, dy                in (-2^32, 2^32)
//   q = dx^2 + dy^2       < 2^65
//   R^2, D^2              < 2^64
//   low + high            <= 2 * (D + 1) <= 2^33
//   mid^2                 <= 2^64
inline constexpr Word kMaxSquaredDistance = (Word{1} << 65);

inline Word encode_signed(std::int64_t value) {
    return static_cast<Word>(static_cast<SignedWord>(value));
}

inline SignedWord decode_signed(Word value) {
    return static_cast<SignedWord>(value);
}

inline Word encode_coordinate(std::int64_t value) {
    if (value < kCoordinateMin || value > kCoordinateMax) {
        throw std::out_of_range("coordinate outside signed 32-bit domain");
    }
    return encode_signed(value);
}

inline Word encode_radius(std::uint64_t value) {
    if (value > kRadiusMax) {
        throw std::out_of_range("support radius outside unsigned 32-bit domain");
    }
    return static_cast<Word>(value);
}

inline void store_le(Word value, std::uint8_t* out) {
    for (int i = 0; i < 16; ++i) {
        out[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

inline Word load_le(const std::uint8_t* in) {
    Word value = 0;
    for (int i = 15; i >= 0; --i) {
        value = (value << 8) | in[i];
    }
    return value;
}

inline std::string to_decimal(SignedWord value) {
    if (value == 0) {
        return "0";
    }
    const bool negative = value < 0;
    Word magnitude = negative ? Word(0) - static_cast<Word>(value) : static_cast<Word>(value);
    std::string digits;
    while (magnitude != 0) {
        digits.insert(digits.begin(), static_cast<char>('0' + static_cast<int>(magnitude % 10)));
        magnitude /= 10;
    }
    return negative ? "-" + digits : digits;
}

}  // namespace pps

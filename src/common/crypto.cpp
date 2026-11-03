#include "common/crypto.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <stdexcept>

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

std::array<std::uint8_t, 32> sha256(const std::vector<std::uint8_t>& data) {
    std::array<std::uint8_t, 32> digest{};
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 ||
        length != digest.size()) {
        throw std::runtime_error("SHA-256 failure");
    }
    return digest;
}

}  // namespace pps

// SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), from scratch. This port
// implements them itself rather than delegating to a crypto library.
#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace dorado::sha256 {

std::array<std::uint8_t, 32> hash(std::span<const std::uint8_t> msg);

std::array<std::uint8_t, 32> hmac(std::span<const std::uint8_t> key,
                                  std::span<const std::uint8_t> msg);

}  // namespace dorado::sha256

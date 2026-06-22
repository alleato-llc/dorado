// Password key-derivation functions, delegated to OpenSSL's EVP_KDF (Argon2id,
// scrypt, PBKDF2-HMAC-SHA256), matching the other ports' use of a KDF library.
// The cipher and hashes (incl. SHA-256/HMAC) are from scratch; only these are not.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace dorado::kdf {

struct Argon2id {
  std::uint32_t m_cost;  // memory in KiB
  std::uint32_t t_cost;  // iterations
  std::uint32_t p_cost;  // lanes
};
struct Scrypt {
  std::uint8_t log_n;
  std::uint32_t r;
  std::uint32_t p;
};
struct Pbkdf2 {
  std::uint32_t rounds;  // PRF is HMAC-SHA256
};

using Kdf = std::variant<Argon2id, Scrypt, Pbkdf2>;

// Derive `out_len` key bytes. Throws std::runtime_error on an OpenSSL failure.
std::vector<std::uint8_t> derive(const Kdf& kdf, std::span<const std::uint8_t> password,
                                 std::span<const std::uint8_t> salt, std::size_t out_len);

}  // namespace dorado::kdf

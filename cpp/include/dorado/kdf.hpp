// Key derivation, in its two standard forms. `derive` is password-based
// derivation (a PBKDF): it stretches a weak, guessable secret deliberately
// slowly, delegated to OpenSSL's EVP_KDF (Argon2id, scrypt,
// PBKDF2-HMAC-SHA256), matching the other ports' use of a KDF library;
// `validate` bounds untrusted cost parameters. `derive_from_key` is key-based
// derivation (a KBKDF): it splits an already high-entropy key into
// independent, domain-separated children, fast (one keyed hash), built on the
// port's own from-scratch Skein-512/BLAKE3, with no salt and no cost
// parameters because there is nothing to stretch. The names are the guardrail:
// a password must never take the fast path (no stretching), and a key never
// needs the slow one.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
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

// Reject KDF parameters whose cost is unreasonably large. Decryption reads the
// cost from an untrusted file header, so without this a crafted file could
// request gigabytes of memory or a multi-minute derivation (a denial of
// service). The caps are generous, well above any sane real-world setting.
std::expected<void, std::string> validate(const Kdf& kdf);

// The keyed hash `derive_from_key_with` fans a master key out with. Both are
// secure PRFs and produce identically strong children; the choice exists only
// to let a construction stay within one cryptographic family (Skein for
// Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
enum class KdfPrf : std::uint8_t {
  // Skein-512 keyed hash (Threefish's native companion). The default, and
  // what derive_from_key uses. Accepts a key of any length.
  Skein512,
  // BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's keyed mode is defined
  // only for a 256-bit key); other lengths are an error.
  Blake3,
};

// Derive `out_len` key bytes from an already high-entropy `key`, separated by
// `domain` -- key-based derivation (the fast form): one domain-separated
// Skein-512 keyed hash, no salt, no cost parameters, because a strong key has
// nothing to stretch. Deterministic: the same key and domain always yield the
// same bytes, and different domains yield computationally unrelated ones, so a
// caller can fan one master key out into independent per-purpose keys
// (derive_from_key(master, "myapp/index", 32), derive_from_key(master,
// "myapp/data", 32)). Never pass a password here: there is no stretching, so a
// guessable input stays guessable -- that is `derive`'s job. To fan out with a
// different PRF (e.g. BLAKE3), use derive_from_key_with.
std::vector<std::uint8_t> derive_from_key(std::span<const std::uint8_t> key,
                                          std::string_view domain, std::size_t out_len);

// derive_from_key with a caller-chosen PRF (KdfPrf). The domain separation,
// determinism, and "never pass a password" contract are exactly the same; only
// the underlying keyed hash changes. With KdfPrf::Skein512 this is
// byte-for-byte identical to derive_from_key. KdfPrf::Blake3 requires `key` to
// be 32 bytes and errors on any other length.
std::expected<std::vector<std::uint8_t>, std::string> derive_from_key_with(
    KdfPrf prf, std::span<const std::uint8_t> key, std::string_view domain, std::size_t out_len);

}  // namespace dorado::kdf

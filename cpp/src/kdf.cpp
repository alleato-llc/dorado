#include "dorado/kdf.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <array>
#include <stdexcept>
#include <string>

#include "dorado/blake3.hpp"
#include "dorado/skein.hpp"

namespace dorado::kdf {
namespace {

// Fixed prefix domain-separating derive_from_key's keyed hashing from every
// other keyed use in the engine (DRDOrawE/DRDOrawM in the raw-key split,
// DRDOchnk/DRDOrwFr in the frame MACs).
constexpr std::array<std::uint8_t, 8> kDeriveFromKeyDomain = {'D', 'R', 'D', 'O',
                                                             'k', 'd', 'r', 'v'};

// Run an EVP_KDF named `name` with `params` into a buffer of `out_len` bytes.
std::vector<std::uint8_t> run(const char* name, OSSL_PARAM* params, std::size_t out_len) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, name, nullptr);
  if (kdf == nullptr) throw std::runtime_error(std::string("EVP_KDF_fetch failed for ") + name);
  EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (ctx == nullptr) throw std::runtime_error("EVP_KDF_CTX_new failed");
  std::vector<std::uint8_t> out(out_len);
  int rc = EVP_KDF_derive(ctx, out.data(), out.size(), params);
  EVP_KDF_CTX_free(ctx);
  if (rc <= 0) throw std::runtime_error(std::string("EVP_KDF_derive failed for ") + name);
  return out;
}

void* cast(std::span<const std::uint8_t> s) {
  return const_cast<std::uint8_t*>(s.data());
}

}  // namespace

std::vector<std::uint8_t> derive(const Kdf& kdf, std::span<const std::uint8_t> password,
                                 std::span<const std::uint8_t> salt, std::size_t out_len) {
  return std::visit(
      [&](const auto& k) -> std::vector<std::uint8_t> {
        using T = std::decay_t<decltype(k)>;
        if constexpr (std::is_same_v<T, Argon2id>) {
          std::uint32_t iter = k.t_cost, mem = k.m_cost, lanes = k.p_cost, threads = 1;
          OSSL_PARAM params[] = {
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, cast(password), password.size()),
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, cast(salt), salt.size()),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_THREADS, &threads),
              OSSL_PARAM_construct_end()};
          return run("ARGON2ID", params, out_len);
        } else if constexpr (std::is_same_v<T, Scrypt>) {
          std::uint64_t n = std::uint64_t(1) << k.log_n;
          std::uint32_t r = k.r, p = k.p;
          OSSL_PARAM params[] = {
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, cast(password), password.size()),
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, cast(salt), salt.size()),
              OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_R, &r),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_P, &p),
              OSSL_PARAM_construct_end()};
          return run("SCRYPT", params, out_len);
        } else {  // Pbkdf2
          std::uint32_t iter = k.rounds;
          int pkcs5 = 1;  // allow arbitrary salt/iteration/key sizes (plain PBKDF2)
          char digest[] = "SHA256";
          OSSL_PARAM params[] = {
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, cast(password), password.size()),
              OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, cast(salt), salt.size()),
              OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter),
              OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
              OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5),
              OSSL_PARAM_construct_end()};
          return run("PBKDF2", params, out_len);
        }
      },
      kdf);
}

std::expected<void, std::string> validate(const Kdf& kdf) {
  return std::visit(
      [](const auto& k) -> std::expected<void, std::string> {
        using T = std::decay_t<decltype(k)>;
        if constexpr (std::is_same_v<T, Argon2id>) {
          if (k.m_cost > 1u << 21) return std::unexpected("argon2 memory cost too large");  // > 2 GiB
          if (k.t_cost > 64) return std::unexpected("argon2 time cost too large");
          if (k.p_cost > 16) return std::unexpected("argon2 parallelism too large");
        } else if constexpr (std::is_same_v<T, Scrypt>) {
          if (k.log_n > 21) return std::unexpected("scrypt cost (log2 N) too large");
          if (k.r > 32) return std::unexpected("scrypt block factor r too large");
          if (k.p > 16) return std::unexpected("scrypt parallelism p too large");
        } else {  // Pbkdf2
          // Zero rounds would "derive" an all-zero key without error.
          if (k.rounds == 0) return std::unexpected("pbkdf2 rounds must be nonzero");
          if (k.rounds > 50'000'000) return std::unexpected("pbkdf2 rounds too large");
        }
        return {};
      },
      kdf);
}

std::vector<std::uint8_t> derive_from_key(std::span<const std::uint8_t> key,
                                          std::string_view domain, std::size_t out_len) {
  // Defined as the Skein-512 case of derive_from_key_with, which accepts a key
  // of any length, so this cannot fail.
  return *derive_from_key_with(KdfPrf::Skein512, key, domain, out_len);
}

std::expected<std::vector<std::uint8_t>, std::string> derive_from_key_with(
    KdfPrf prf, std::span<const std::uint8_t> key, std::string_view domain, std::size_t out_len) {
  // One message, PRF(key, "DRDOkdrv" || domain), matching the Rust reference
  // and docs/fixtures/derive-from-key.md.
  std::vector<std::uint8_t> msg(kDeriveFromKeyDomain.begin(), kDeriveFromKeyDomain.end());
  msg.insert(msg.end(), domain.begin(), domain.end());
  switch (prf) {
    case KdfPrf::Skein512:
      return skein::mac(key, out_len, msg);
    case KdfPrf::Blake3:
      if (key.size() != 32)
        return std::unexpected("derive_from_key_with(Blake3) requires a 32-byte key, got " +
                               std::to_string(key.size()));
      return blake3::keyed_mac(key, out_len, msg);
  }
  return std::unexpected("unknown kdf prf");
}

}  // namespace dorado::kdf

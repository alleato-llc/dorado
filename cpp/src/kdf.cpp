#include "dorado/kdf.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <stdexcept>
#include <string>

namespace dorado::kdf {
namespace {

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

}  // namespace dorado::kdf

#include "dorado/sha256.hpp"

#include <algorithm>
#include <bit>
#include <vector>

#include "internal.hpp"

namespace dorado::sha256 {
namespace {

constexpr std::uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

constexpr std::uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

std::uint32_t bsig0(std::uint32_t x) { return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22); }
std::uint32_t bsig1(std::uint32_t x) { return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25); }
std::uint32_t ssig0(std::uint32_t x) { return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3); }
std::uint32_t ssig1(std::uint32_t x) { return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10); }
std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (~x & z); }
std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

void process(std::array<std::uint32_t, 8>& h, const std::uint8_t* block) {
  std::uint32_t w[64];
  for (int t = 0; t < 16; ++t) w[t] = detail::load_be32(block + t * 4);
  for (int t = 16; t < 64; ++t)
    w[t] = ssig1(w[t - 2]) + w[t - 7] + ssig0(w[t - 15]) + w[t - 16];
  std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int t = 0; t < 64; ++t) {
    std::uint32_t t1 = hh + bsig1(e) + ch(e, f, g) + K[t] + w[t];
    std::uint32_t t2 = bsig0(a) + maj(a, b, c);
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

}  // namespace

std::array<std::uint8_t, 32> hash(std::span<const std::uint8_t> msg) {
  std::array<std::uint32_t, 8> h;
  for (int i = 0; i < 8; ++i) h[i] = H0[i];

  std::vector<std::uint8_t> m(msg.begin(), msg.end());
  std::uint64_t bitlen = std::uint64_t(msg.size()) * 8;
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0);
  std::uint8_t lenbytes[8];
  detail::store_be64(lenbytes, bitlen);
  m.insert(m.end(), lenbytes, lenbytes + 8);

  for (std::size_t off = 0; off < m.size(); off += 64) process(h, &m[off]);

  std::array<std::uint8_t, 32> out{};
  for (int i = 0; i < 8; ++i) detail::store_be32(&out[i * 4], h[i]);
  return out;
}

std::array<std::uint8_t, 32> hmac(std::span<const std::uint8_t> key,
                                  std::span<const std::uint8_t> msg) {
  constexpr int B = 64;
  std::array<std::uint8_t, B> k0{};
  if (key.size() > std::size_t(B)) {
    auto kh = hash(key);
    std::copy(kh.begin(), kh.end(), k0.begin());
  } else {
    std::copy(key.begin(), key.end(), k0.begin());
  }
  std::array<std::uint8_t, B> ipad, opad;
  for (int i = 0; i < B; ++i) {
    ipad[i] = k0[i] ^ 0x36;
    opad[i] = k0[i] ^ 0x5c;
  }
  std::vector<std::uint8_t> inner(ipad.begin(), ipad.end());
  inner.insert(inner.end(), msg.begin(), msg.end());
  auto inner_hash = hash(inner);
  std::vector<std::uint8_t> outer(opad.begin(), opad.end());
  outer.insert(outer.end(), inner_hash.begin(), inner_hash.end());
  return hash(outer);
}

}  // namespace dorado::sha256

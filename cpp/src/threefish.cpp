#include "dorado/threefish.hpp"

#include <algorithm>
#include <bit>
#include <vector>

namespace dorado {
namespace {

constexpr std::uint64_t C240 = 0x1BD11BDAA9FC1A22ULL;

// Per-variant rotation constants (Skein 1.3, Table 4): rot[lane][round % 8].
constexpr std::uint32_t ROT_256[2][8] = {
    {14, 52, 23, 5, 25, 46, 58, 32},
    {16, 57, 40, 37, 33, 12, 22, 32},
};
constexpr int PERM_256[4] = {0, 3, 2, 1};

constexpr std::uint32_t ROT_512[4][8] = {
    {46, 33, 17, 44, 39, 13, 25, 8},
    {36, 27, 49, 9, 30, 50, 29, 35},
    {19, 14, 36, 54, 34, 10, 39, 56},
    {37, 42, 39, 56, 24, 17, 43, 22},
};
constexpr int PERM_512[8] = {2, 1, 4, 7, 6, 5, 0, 3};

constexpr std::uint32_t ROT_1024[8][8] = {
    {24, 38, 33, 5, 41, 16, 31, 9},
    {13, 19, 4, 20, 9, 34, 44, 48},
    {8, 10, 51, 48, 37, 56, 47, 35},
    {47, 55, 13, 41, 31, 51, 46, 52},
    {8, 49, 34, 47, 12, 4, 19, 23},
    {17, 18, 41, 28, 47, 53, 42, 31},
    {22, 23, 59, 16, 44, 42, 44, 37},
    {37, 52, 17, 25, 30, 41, 25, 20},
};
constexpr int PERM_1024[16] = {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};

std::uint64_t load_le64(const std::uint8_t* p) {
  std::uint64_t w = 0;
  for (int i = 0; i < 8; ++i) w |= std::uint64_t(p[i]) << (8 * i);
  return w;
}

void store_le64(std::uint8_t* p, std::uint64_t w) {
  for (int i = 0; i < 8; ++i) p[i] = std::uint8_t(w >> (8 * i));
}

}  // namespace

Threefish::Threefish(Variant v, std::span<const std::uint8_t> key,
                     std::span<const std::uint8_t> tweak)
    : v_(v) {
  nw_ = block_size(v) / 8;
  switch (v) {
    case Variant::TF256: rounds_ = 72; rot_ = ROT_256; perm_ = PERM_256; break;
    case Variant::TF512: rounds_ = 72; rot_ = ROT_512; perm_ = PERM_512; break;
    case Variant::TF1024: rounds_ = 80; rot_ = ROT_1024; perm_ = PERM_1024; break;
  }
  std::uint64_t parity = C240;
  for (int i = 0; i < nw_; ++i) {
    std::uint64_t k = load_le64(&key[i * 8]);
    ek_[i] = k;
    parity ^= k;
  }
  ek_[nw_] = parity;
  std::uint64_t t0 = load_le64(&tweak[0]);
  std::uint64_t t1 = load_le64(&tweak[8]);
  et_[0] = t0;
  et_[1] = t1;
  et_[2] = t0 ^ t1;
}

// The i-th word of subkey s: a key word, with the two tweak words and the round
// counter folded into the top three positions.
std::uint64_t Threefish::subkey_word(int s, int i) const {
  std::uint64_t k = ek_[(s + i) % (nw_ + 1)];
  if (i == nw_ - 3) k += et_[s % 3];
  else if (i == nw_ - 2) k += et_[(s + 1) % 3];
  else if (i == nw_ - 1) k += std::uint64_t(s);
  return k;
}

void Threefish::encrypt_block(std::span<std::uint8_t> block) const {
  std::array<std::uint64_t, 16> st{};
  std::array<std::uint64_t, 16> scratch{};
  for (int i = 0; i < nw_; ++i) st[i] = load_le64(&block[i * 8]);

  for (int r = 0; r < rounds_; ++r) {
    if (r % 4 == 0) {
      int s = r / 4;
      for (int i = 0; i < nw_; ++i) st[i] += subkey_word(s, i);
    }
    for (int j = 0; j < nw_ / 2; ++j) {
      std::uint64_t x0 = st[2 * j], x1 = st[2 * j + 1];
      std::uint64_t y0 = x0 + x1;
      std::uint64_t y1 = std::rotl(x1, static_cast<int>(rot_[j][r % 8])) ^ y0;
      st[2 * j] = y0;
      st[2 * j + 1] = y1;
    }
    for (int i = 0; i < nw_; ++i) scratch[i] = st[perm_[i]];
    for (int i = 0; i < nw_; ++i) st[i] = scratch[i];
  }
  int s = rounds_ / 4;
  for (int i = 0; i < nw_; ++i) st[i] += subkey_word(s, i);

  for (int i = 0; i < nw_; ++i) store_le64(&block[i * 8], st[i]);
}

void Threefish::decrypt_block(std::span<std::uint8_t> block) const {
  std::array<std::uint64_t, 16> st{};
  std::array<std::uint64_t, 16> scratch{};
  for (int i = 0; i < nw_; ++i) st[i] = load_le64(&block[i * 8]);

  int sf = rounds_ / 4;
  for (int i = 0; i < nw_; ++i) st[i] -= subkey_word(sf, i);

  for (int r = rounds_ - 1; r >= 0; --r) {
    for (int i = 0; i < nw_; ++i) scratch[perm_[i]] = st[i];
    for (int i = 0; i < nw_; ++i) st[i] = scratch[i];
    for (int j = 0; j < nw_ / 2; ++j) {
      std::uint64_t y0 = st[2 * j], y1 = st[2 * j + 1];
      std::uint64_t x1 = std::rotr(y1 ^ y0, static_cast<int>(rot_[j][r % 8]));
      std::uint64_t x0 = y0 - x1;
      st[2 * j] = x0;
      st[2 * j + 1] = x1;
    }
    if (r % 4 == 0) {
      int s = r / 4;
      for (int i = 0; i < nw_; ++i) st[i] -= subkey_word(s, i);
    }
  }
  for (int i = 0; i < nw_; ++i) store_le64(&block[i * 8], st[i]);
}

void Threefish::ctr_apply(std::span<const std::uint8_t> iv, std::span<std::uint8_t> data) const {
  const int bs = block_size(v_);
  std::vector<std::uint8_t> counter(iv.begin(), iv.end());
  std::vector<std::uint8_t> ks(bs);
  std::size_t off = 0;
  while (off < data.size()) {
    std::copy(counter.begin(), counter.end(), ks.begin());
    encrypt_block(ks);
    std::size_t n = std::min<std::size_t>(bs, data.size() - off);
    for (std::size_t i = 0; i < n; ++i) data[off + i] ^= ks[i];
    off += n;
    // Increment the counter as a big-endian integer, wrapping on overflow.
    for (int i = bs - 1; i >= 0; --i) {
      if (++counter[i] != 0) break;
    }
  }
}

}  // namespace dorado

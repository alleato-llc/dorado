#include "dorado/skein.hpp"

#include <algorithm>

#include "dorado/threefish.hpp"
#include "internal.hpp"

namespace dorado::skein {
namespace {

constexpr int BLOCK = 64;
constexpr std::uint64_t T_KEY = 0, T_CFG = 4, T_MSG = 48, T_OUT = 63;

// The 128-bit UBI tweak (16 little-endian bytes): position, type (bits 120-125),
// first (bit 126), final (bit 127).
std::array<std::uint8_t, 16> tweak(std::uint64_t position, std::uint64_t ty, bool first, bool last) {
  std::uint64_t t1 = ty << 56;
  if (first) t1 |= std::uint64_t(1) << 62;
  if (last) t1 |= std::uint64_t(1) << 63;
  std::array<std::uint8_t, 16> tw{};
  detail::store_le64(&tw[0], position);
  detail::store_le64(&tw[8], t1);
  return tw;
}

// One UBI pass: chain `msg` into the 64-byte chaining value `g` under type `ty`.
void ubi(std::array<std::uint8_t, 64>& g, std::span<const std::uint8_t> msg, std::uint64_t ty) {
  const std::size_t total = msg.size();
  std::size_t offset = 0;
  std::uint64_t position = 0;
  bool first = true;
  for (;;) {
    std::size_t take = std::min<std::size_t>(BLOCK, total - offset);
    std::array<std::uint8_t, 64> block{};
    std::copy(msg.begin() + offset, msg.begin() + offset + take, block.begin());
    position += take;
    offset += take;
    bool last = offset >= total;
    Threefish c(Variant::TF512, g, tweak(position, ty, first, last));
    std::array<std::uint8_t, 64> enc = block;
    c.encrypt_block(enc);
    for (int i = 0; i < 64; ++i) g[i] = enc[i] ^ block[i];
    first = false;
    if (last) break;
  }
}

std::array<std::uint8_t, 32> config_block(std::uint64_t out_bits) {
  std::array<std::uint8_t, 32> c{};
  c[0] = 'S'; c[1] = 'H'; c[2] = 'A'; c[3] = '3';
  c[4] = 1;  // version 1
  detail::store_le64(&c[8], out_bits);
  return c;
}

void output_into(const std::array<std::uint8_t, 64>& g, std::uint8_t* out, std::size_t len) {
  std::uint64_t counter = 0;
  std::size_t written = 0;
  while (written < len) {
    std::array<std::uint8_t, 64> block = g;
    std::array<std::uint8_t, 8> cb{};
    detail::store_le64(cb.data(), counter);
    ubi(block, cb, T_OUT);
    std::size_t n = std::min<std::size_t>(BLOCK, len - written);
    std::copy(block.begin(), block.begin() + n, out + written);
    written += n;
    ++counter;
  }
}

}  // namespace

std::vector<std::uint8_t> hash(std::size_t out_len, std::span<const std::uint8_t> msg) {
  std::array<std::uint8_t, 64> g{};
  ubi(g, config_block(std::uint64_t(out_len) * 8), T_CFG);
  ubi(g, msg, T_MSG);
  std::vector<std::uint8_t> out(out_len);
  output_into(g, out.data(), out_len);
  return out;
}

std::vector<std::uint8_t> mac(std::span<const std::uint8_t> key, std::size_t out_len,
                              std::span<const std::uint8_t> msg) {
  std::array<std::uint8_t, 64> g{};
  if (!key.empty()) ubi(g, key, T_KEY);
  ubi(g, config_block(std::uint64_t(out_len) * 8), T_CFG);
  ubi(g, msg, T_MSG);
  std::vector<std::uint8_t> out(out_len);
  output_into(g, out.data(), out_len);
  return out;
}

Hasher::Hasher(std::size_t out_len) : out_len_(out_len) {
  ubi(g_, config_block(std::uint64_t(out_len) * 8), T_CFG);
}

void Hasher::commit(std::span<const std::uint8_t> blk, bool last) {
  pos_ += blk.size();
  std::array<std::uint8_t, 64> padded{};
  std::copy(blk.begin(), blk.end(), padded.begin());
  Threefish c(Variant::TF512, g_, tweak(pos_, T_MSG, first_, last));
  std::array<std::uint8_t, 64> enc = padded;
  c.encrypt_block(enc);
  for (int i = 0; i < 64; ++i) g_[i] = enc[i] ^ padded[i];
  first_ = false;
}

void Hasher::update(std::span<const std::uint8_t> data) {
  buf_.insert(buf_.end(), data.begin(), data.end());
  while (buf_.size() > std::size_t(BLOCK)) {
    commit(std::span<const std::uint8_t>(buf_.data(), BLOCK), false);
    buf_.erase(buf_.begin(), buf_.begin() + BLOCK);
  }
}

std::vector<std::uint8_t> Hasher::finalize() {
  commit(std::span<const std::uint8_t>(buf_.data(), buf_.size()), true);
  std::vector<std::uint8_t> out(out_len_);
  output_into(g_, out.data(), out_len_);
  return out;
}

}  // namespace dorado::skein

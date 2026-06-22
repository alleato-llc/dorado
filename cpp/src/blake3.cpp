#include "dorado/blake3.hpp"

#include <algorithm>
#include <array>
#include <bit>

#include "internal.hpp"

namespace dorado::blake3 {
namespace {

constexpr int BLOCK_LEN = 64, CHUNK_LEN = 1024;
constexpr std::uint32_t CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8, KEYED_HASH = 16;
constexpr std::uint32_t IV[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                                 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
constexpr int MSG_PERMUTATION[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

using Cv = std::array<std::uint32_t, 8>;
using Block = std::array<std::uint32_t, 16>;

void g(std::array<std::uint32_t, 16>& s, int a, int b, int c, int d, std::uint32_t mx,
       std::uint32_t my) {
  s[a] = s[a] + s[b] + mx;
  s[d] = std::rotr(s[d] ^ s[a], 16);
  s[c] = s[c] + s[d];
  s[b] = std::rotr(s[b] ^ s[c], 12);
  s[a] = s[a] + s[b] + my;
  s[d] = std::rotr(s[d] ^ s[a], 8);
  s[c] = s[c] + s[d];
  s[b] = std::rotr(s[b] ^ s[c], 7);
}

std::array<std::uint32_t, 16> compress(const Cv& cv, const Block& block, std::uint64_t counter,
                                       std::uint32_t block_len, std::uint32_t flags) {
  std::array<std::uint32_t, 16> s = {
      cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
      IV[0], IV[1], IV[2], IV[3], std::uint32_t(counter), std::uint32_t(counter >> 32),
      block_len, flags};
  Block m = block;
  for (int round = 0; round < 7; ++round) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
    if (round < 6) {
      Block p;
      for (int i = 0; i < 16; ++i) p[i] = m[MSG_PERMUTATION[i]];
      m = p;
    }
  }
  for (int i = 0; i < 8; ++i) {
    s[i] ^= s[i + 8];
    s[i + 8] ^= cv[i];
  }
  return s;
}

Block words_from_block(std::span<const std::uint8_t> bytes) {
  std::array<std::uint8_t, 64> padded{};
  std::copy(bytes.begin(), bytes.end(), padded.begin());
  Block w{};
  for (int i = 0; i < 16; ++i) w[i] = detail::load_le32(&padded[i * 4]);
  return w;
}

struct Output {
  Cv input_cv;
  Block block;
  std::uint64_t counter;
  std::uint32_t block_len;
  std::uint32_t flags;
};

Cv chaining_value(const Output& o) {
  auto full = compress(o.input_cv, o.block, o.counter, o.block_len, o.flags);
  Cv cv;
  for (int i = 0; i < 8; ++i) cv[i] = full[i];
  return cv;
}

void root_output_into(const Output& o, std::uint8_t* out, std::size_t len) {
  std::uint64_t counter = 0;
  std::size_t written = 0;
  while (written < len) {
    auto words = compress(o.input_cv, o.block, counter, o.block_len, o.flags | ROOT);
    for (int i = 0; i < 16 && written < len; ++i) {
      std::uint8_t b[4];
      detail::store_le32(b, words[i]);
      std::size_t n = std::min<std::size_t>(4, len - written);
      std::copy(b, b + n, out + written);
      written += n;
    }
    ++counter;
  }
}

Output chunk_output(const Cv& key, std::uint64_t counter, std::uint32_t base_flags,
                    std::span<const std::uint8_t> chunk) {
  Cv cv = key;
  std::size_t compressed = 0;
  std::span<const std::uint8_t> bytes = chunk;
  while (bytes.size() > std::size_t(BLOCK_LEN)) {
    std::uint32_t flags = base_flags | (compressed == 0 ? CHUNK_START : 0);
    auto out = compress(cv, words_from_block(bytes.subspan(0, BLOCK_LEN)), counter, BLOCK_LEN, flags);
    for (int i = 0; i < 8; ++i) cv[i] = out[i];
    ++compressed;
    bytes = bytes.subspan(BLOCK_LEN);
  }
  std::uint32_t flags = base_flags | (compressed == 0 ? CHUNK_START : 0) | CHUNK_END;
  return Output{cv, words_from_block(bytes), counter, std::uint32_t(bytes.size()), flags};
}

Output parent_output(const Cv& left, const Cv& right, const Cv& key, std::uint32_t base_flags) {
  Block block;
  for (int i = 0; i < 8; ++i) {
    block[i] = left[i];
    block[8 + i] = right[i];
  }
  return Output{key, block, 0, BLOCK_LEN, base_flags | PARENT};
}

Cv parent_cv(const Cv& l, const Cv& r, const Cv& key, std::uint32_t flags) {
  return chaining_value(parent_output(l, r, key, flags));
}

std::vector<std::uint8_t> root_bytes(const Cv& key, std::uint32_t flags,
                                     std::span<const std::uint8_t> input, std::size_t out_len) {
  std::vector<std::span<const std::uint8_t>> chunks;
  if (input.empty()) {
    chunks.push_back(input);
  } else {
    for (std::size_t i = 0; i < input.size(); i += CHUNK_LEN)
      chunks.push_back(input.subspan(i, std::min<std::size_t>(CHUNK_LEN, input.size() - i)));
  }
  std::size_t n = chunks.size();

  std::vector<Cv> stack;  // back() is the top
  auto add_chunk_cv = [&](Cv new_cv, std::uint64_t total_chunks) {
    while ((total_chunks & 1) == 0) {
      Cv left = stack.back();
      stack.pop_back();
      new_cv = parent_cv(left, new_cv, key, flags);
      total_chunks >>= 1;
    }
    stack.push_back(new_cv);
  };
  for (std::size_t i = 0; i + 1 < n; ++i)
    add_chunk_cv(chaining_value(chunk_output(key, i, flags, chunks[i])), std::uint64_t(i) + 1);

  Output out = chunk_output(key, n - 1, flags, chunks[n - 1]);
  for (auto it = stack.rbegin(); it != stack.rend(); ++it)
    out = parent_output(*it, chaining_value(out), key, flags);

  std::vector<std::uint8_t> result(out_len);
  root_output_into(out, result.data(), out_len);
  return result;
}

}  // namespace

std::vector<std::uint8_t> hash(std::size_t out_len, std::span<const std::uint8_t> input) {
  Cv iv;
  for (int i = 0; i < 8; ++i) iv[i] = IV[i];
  return root_bytes(iv, 0, input, out_len);
}

std::vector<std::uint8_t> keyed_mac(std::span<const std::uint8_t> key, std::size_t out_len,
                                    std::span<const std::uint8_t> input) {
  Cv kw;
  for (int i = 0; i < 8; ++i) kw[i] = detail::load_le32(&key[i * 4]);
  return root_bytes(kw, KEYED_HASH, input, out_len);
}

}  // namespace dorado::blake3

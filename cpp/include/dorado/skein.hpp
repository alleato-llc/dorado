// Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI (Unique
// Block Iteration). From scratch; verified against the Rust reference's digests.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dorado::skein {

// Skein-512 hash of `msg` producing `out_len` bytes.
std::vector<std::uint8_t> hash(std::size_t out_len, std::span<const std::uint8_t> msg);

// Skein-512 MAC (keyed hash): absorbs `key` through a Key UBI first.
std::vector<std::uint8_t> mac(std::span<const std::uint8_t> key, std::size_t out_len,
                              std::span<const std::uint8_t> msg);

// Incremental unkeyed hasher for streaming inputs larger than memory (gyotaku).
// Produces the same digest as `hash` at any chunking.
class Hasher {
 public:
  explicit Hasher(std::size_t out_len);
  void update(std::span<const std::uint8_t> data);
  std::vector<std::uint8_t> finalize();

 private:
  void commit(std::span<const std::uint8_t> blk, bool last);

  std::array<std::uint8_t, 64> g_{};
  std::vector<std::uint8_t> buf_;
  std::uint64_t pos_ = 0;
  bool first_ = true;
  std::size_t out_len_;
};

}  // namespace dorado::skein

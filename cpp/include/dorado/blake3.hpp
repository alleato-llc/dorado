// BLAKE3 hash and keyed MAC, from scratch (Merkle-tree hash over 1024-byte
// chunks). Extendable output: out_len may exceed 32. Verified against the Rust
// reference and the official BLAKE3 vectors.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace dorado::blake3 {

std::vector<std::uint8_t> hash(std::size_t out_len, std::span<const std::uint8_t> input);

// Keyed MAC under a 32-byte key.
std::vector<std::uint8_t> keyed_mac(std::span<const std::uint8_t> key, std::size_t out_len,
                                    std::span<const std::uint8_t> input);

}  // namespace dorado::blake3

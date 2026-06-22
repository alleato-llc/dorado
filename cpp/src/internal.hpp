// Internal little/big-endian byte helpers shared across the from-scratch modules.
// Not part of the public API.
#pragma once

#include <cstddef>
#include <cstdint>

namespace dorado::detail {

// Overwrite `n` bytes at `p` with zero so the compiler cannot elide the store.
// Writes through a volatile lvalue are observable behavior the standard forbids
// optimizing away, so this is the portable analog of OPENSSL_cleanse / secureZero.
// (Like all such wipes it cannot scrub copies the compiler may have spilled to
// registers earlier; it clears the buffer itself.)
inline void secure_wipe(void* p, std::size_t n) noexcept {
  if (p == nullptr) return;
  volatile std::uint8_t* v = static_cast<volatile std::uint8_t*>(p);
  for (std::size_t i = 0; i < n; ++i) v[i] = 0;
}

inline std::uint32_t load_le32(const std::uint8_t* p) {
  return std::uint32_t(p[0]) | std::uint32_t(p[1]) << 8 | std::uint32_t(p[2]) << 16 |
         std::uint32_t(p[3]) << 24;
}

inline void store_le32(std::uint8_t* p, std::uint32_t w) {
  for (int i = 0; i < 4; ++i) p[i] = std::uint8_t(w >> (8 * i));
}

inline std::uint64_t load_le64(const std::uint8_t* p) {
  std::uint64_t w = 0;
  for (int i = 0; i < 8; ++i) w |= std::uint64_t(p[i]) << (8 * i);
  return w;
}

inline void store_le64(std::uint8_t* p, std::uint64_t w) {
  for (int i = 0; i < 8; ++i) p[i] = std::uint8_t(w >> (8 * i));
}

inline std::uint32_t load_be32(const std::uint8_t* p) {
  return std::uint32_t(p[0]) << 24 | std::uint32_t(p[1]) << 16 | std::uint32_t(p[2]) << 8 |
         std::uint32_t(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t w) {
  for (int i = 0; i < 4; ++i) p[i] = std::uint8_t(w >> (8 * (3 - i)));
}

inline void store_be64(std::uint8_t* p, std::uint64_t w) {
  for (int i = 0; i < 8; ++i) p[i] = std::uint8_t(w >> (8 * (7 - i)));
}

}  // namespace dorado::detail

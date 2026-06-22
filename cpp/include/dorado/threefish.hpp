// Threefish tweakable block cipher (256/512/1024-bit) following the Skein 1.3
// specification, plus CTR mode. From-scratch, pure-ARX (add / rotate / xor), no
// lookup tables. Verified against the official Crypto++ known-answer vectors.
//
// This is the C++ port of the dorado Rust crate's cipher core.
#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace dorado {

enum class Variant { TF256, TF512, TF1024 };

// Block size (== key size == IV size) in bytes for a variant.
constexpr int block_size(Variant v) {
  switch (v) {
    case Variant::TF256: return 32;
    case Variant::TF512: return 64;
    case Variant::TF1024: return 128;
  }
  return 0;
}

constexpr int key_size(Variant v) { return block_size(v); }

// A key-scheduled Threefish instance. The key and tweak are little-endian; the
// tweak is 16 bytes. Block operations are in place.
class Threefish {
 public:
  Threefish(Variant v, std::span<const std::uint8_t> key, std::span<const std::uint8_t> tweak);

  void encrypt_block(std::span<std::uint8_t> block) const;
  void decrypt_block(std::span<std::uint8_t> block) const;

  // Apply CTR keystream to `data` in place, starting from counter `iv` (one block
  // wide). The same call encrypts and decrypts.
  void ctr_apply(std::span<const std::uint8_t> iv, std::span<std::uint8_t> data) const;

  Variant variant() const noexcept { return v_; }

 private:
  std::uint64_t subkey_word(int s, int i) const;

  Variant v_;
  int nw_;
  int rounds_;
  const std::uint32_t (*rot_)[8];        // nw_/2 rows of 8 rotation constants
  const int* perm_;                      // nw_ permutation indices
  std::array<std::uint64_t, 17> ek_{};   // extended key, nw_+1 words used
  std::array<std::uint64_t, 3> et_{};    // extended tweak: t0, t1, t0^t1
};

}  // namespace dorado

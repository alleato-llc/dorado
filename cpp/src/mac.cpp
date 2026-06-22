#include "dorado/mac.hpp"

#include "dorado/blake3.hpp"
#include "dorado/sha256.hpp"
#include "dorado/skein.hpp"

namespace dorado::mac {

std::uint8_t mac_id(Mac m) {
  switch (m) {
    case Mac::HmacSha256: return 1;
    case Mac::Skein512: return 2;
    case Mac::Blake3Keyed: return 3;
  }
  return 0;
}

std::optional<Mac> mac_from_id(std::uint8_t id) {
  switch (id) {
    case 1: return Mac::HmacSha256;
    case 2: return Mac::Skein512;
    case 3: return Mac::Blake3Keyed;
    default: return std::nullopt;
  }
}

std::vector<std::uint8_t> tag(Mac m, std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> msg) {
  switch (m) {
    case Mac::HmacSha256: {
      auto t = sha256::hmac(key, msg);
      return std::vector<std::uint8_t>(t.begin(), t.end());
    }
    case Mac::Skein512: return skein::mac(key, 32, msg);
    case Mac::Blake3Keyed: return blake3::keyed_mac(key, 32, msg);
  }
  return {};
}

}  // namespace dorado::mac

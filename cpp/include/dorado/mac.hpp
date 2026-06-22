// The container's MAC menu: HMAC-SHA256, Skein-512, or keyed BLAKE3. All take the
// 32-byte MAC key and produce a 32-byte tag.
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace dorado::mac {

enum class Mac { HmacSha256, Skein512, Blake3Keyed };

std::uint8_t mac_id(Mac m);                  // on-disk id: 1, 2, 3
std::optional<Mac> mac_from_id(std::uint8_t id);

std::vector<std::uint8_t> tag(Mac m, std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> msg);

}  // namespace dorado::mac

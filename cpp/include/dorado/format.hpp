// The DRDO v4 container header: serialize and parse. Byte layout per the shared
// wire format (../docs/spec.md); all multi-byte integers big-endian. Versions 3
// and 4 are read; 4 is written.
#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <vector>

#include "dorado/kdf.hpp"
#include "dorado/mac.hpp"
#include "dorado/threefish.hpp"

namespace dorado::format {

struct Header {
  std::uint8_t version;
  Variant variant;
  kdf::Kdf kdf;
  mac::Mac mac;
  std::uint32_t chunk_size;
  std::vector<std::uint8_t> salt;
  std::vector<std::uint8_t> tweak;  // 16
  std::vector<std::uint8_t> iv;     // block size
  std::vector<std::uint8_t> label;  // empty for v3 / no label
};

std::uint8_t variant_code(Variant v);

std::vector<std::uint8_t> serialize(const Header& h);

struct ParseResult {
  Header header;
  std::size_t consumed;  // header byte length (the rest are frames)
};

std::expected<ParseResult, std::string> parse(std::span<const std::uint8_t> input);

}  // namespace dorado::format

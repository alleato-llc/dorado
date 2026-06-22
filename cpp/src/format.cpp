#include "dorado/format.hpp"

#include <stdexcept>

namespace dorado::format {
namespace {

void put_u16(std::vector<std::uint8_t>& o, std::uint16_t w) {
  o.push_back(std::uint8_t(w >> 8));
  o.push_back(std::uint8_t(w));
}

void put_u32(std::vector<std::uint8_t>& o, std::uint32_t w) {
  for (int i = 3; i >= 0; --i) o.push_back(std::uint8_t(w >> (8 * i)));
}

// A cursor that throws on underflow; parse() catches and returns std::unexpected.
struct Cursor {
  std::span<const std::uint8_t> data;
  std::size_t pos = 0;
  std::span<const std::uint8_t> take(std::size_t n) {
    if (pos + n > data.size()) throw std::runtime_error("unexpected end of input");
    auto s = data.subspan(pos, n);
    pos += n;
    return s;
  }
  std::uint8_t u8() { return take(1)[0]; }
  std::uint16_t u16() {
    auto s = take(2);
    return std::uint16_t(std::uint16_t(s[0]) << 8 | s[1]);
  }
  std::uint32_t u32() {
    auto s = take(4);
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = v << 8 | s[i];
    return v;
  }
};

kdf::Kdf parse_kdf(std::uint8_t id, Cursor& c) {
  switch (id) {
    case 1: {
      std::uint32_t m = c.u32(), t = c.u32(), p = c.u32();
      return kdf::Argon2id{m, t, p};
    }
    case 2: {
      std::uint8_t logn = c.u8();
      std::uint32_t r = c.u32(), p = c.u32();
      return kdf::Scrypt{logn, r, p};
    }
    case 3: {
      std::uint32_t rounds = c.u32();
      std::uint8_t prf = c.u8();
      if (prf != 1) throw std::runtime_error("unknown pbkdf2 prf id");
      return kdf::Pbkdf2{rounds};
    }
    default:
      throw std::runtime_error("unknown kdf id");
  }
}

}  // namespace

std::uint8_t variant_code(Variant v) {
  switch (v) {
    case Variant::TF256: return 0;
    case Variant::TF512: return 1;
    case Variant::TF1024: return 2;
  }
  return 0;
}

std::vector<std::uint8_t> serialize(const Header& h) {
  std::vector<std::uint8_t> o = {'D', 'R', 'D', 'O'};
  o.push_back(h.version);
  o.push_back(variant_code(h.variant));
  std::visit(
      [&](const auto& k) {
        using T = std::decay_t<decltype(k)>;
        if constexpr (std::is_same_v<T, kdf::Argon2id>) {
          o.push_back(1);
          put_u32(o, k.m_cost);
          put_u32(o, k.t_cost);
          put_u32(o, k.p_cost);
        } else if constexpr (std::is_same_v<T, kdf::Scrypt>) {
          o.push_back(2);
          o.push_back(k.log_n);
          put_u32(o, k.r);
          put_u32(o, k.p);
        } else {
          o.push_back(3);
          put_u32(o, k.rounds);
          o.push_back(1);  // prf id = HMAC-SHA256
        }
      },
      h.kdf);
  o.push_back(mac::mac_id(h.mac));
  put_u32(o, h.chunk_size);
  o.push_back(std::uint8_t(h.salt.size()));
  o.insert(o.end(), h.salt.begin(), h.salt.end());
  o.insert(o.end(), h.tweak.begin(), h.tweak.end());
  o.insert(o.end(), h.iv.begin(), h.iv.end());
  if (h.version >= 4) {
    put_u16(o, std::uint16_t(h.label.size()));
    o.insert(o.end(), h.label.begin(), h.label.end());
  }
  return o;
}

std::expected<ParseResult, std::string> parse(std::span<const std::uint8_t> input) {
  try {
    Cursor c{input};
    auto magic = c.take(4);
    if (!(magic[0] == 'D' && magic[1] == 'R' && magic[2] == 'D' && magic[3] == 'O'))
      return std::unexpected("not a dorado container (bad magic)");
    Header h;
    h.version = c.u8();
    if (h.version != 3 && h.version != 4) return std::unexpected("unsupported version");
    std::uint8_t vcode = c.u8();
    switch (vcode) {
      case 0: h.variant = Variant::TF256; break;
      case 1: h.variant = Variant::TF512; break;
      case 2: h.variant = Variant::TF1024; break;
      default: return std::unexpected("unknown variant code");
    }
    h.kdf = parse_kdf(c.u8(), c);
    auto m = mac::mac_from_id(c.u8());
    if (!m) return std::unexpected("unknown mac id");
    h.mac = *m;
    h.chunk_size = c.u32();
    std::uint8_t salt_len = c.u8();
    auto salt = c.take(salt_len);
    h.salt.assign(salt.begin(), salt.end());
    auto tweak = c.take(16);
    h.tweak.assign(tweak.begin(), tweak.end());
    auto iv = c.take(block_size(h.variant));
    h.iv.assign(iv.begin(), iv.end());
    if (h.version >= 4) {
      std::uint16_t ll = c.u16();
      auto label = c.take(ll);
      h.label.assign(label.begin(), label.end());
    }
    return ParseResult{std::move(h), c.pos};
  } catch (const std::exception& e) {
    return std::unexpected(e.what());
  }
}

}  // namespace dorado::format

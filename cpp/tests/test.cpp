// Tests for the C++ port. Currently: Threefish known-answer vectors (official
// Crypto++ threefish.txt values) and CTR self-consistency. A plain assertion
// harness, exiting non-zero on any failure.
#include "dorado/threefish.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

using dorado::Threefish;
using dorado::Variant;
using Bytes = std::vector<std::uint8_t>;

namespace {

int failures = 0;

void check(const std::string& name, bool ok) {
  std::printf("%s %s\n", ok ? "ok  " : "FAIL", name.c_str());
  if (!ok) ++failures;
}

Bytes unhex(const std::string& s) {
  std::string clean;
  for (char c : s)
    if (!std::isspace(static_cast<unsigned char>(c))) clean += c;
  auto hv = [](char c) -> int {
    return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
  };
  Bytes out;
  for (std::size_t i = 0; i + 1 < clean.size(); i += 2)
    out.push_back(static_cast<std::uint8_t>((hv(clean[i]) << 4) | hv(clean[i + 1])));
  return out;
}

const char* kTweak = "000102030405060708090A0B0C0D0E0F";

void kat(const std::string& name, Variant v, const std::string& keyh,
         const std::string& pth, const std::string& cth) {
  Bytes key = unhex(keyh), tweak = unhex(kTweak), pt = unhex(pth), ct = unhex(cth);
  Threefish c(v, key, tweak);
  Bytes b = pt;
  c.encrypt_block(b);
  check(name + " encrypt", b == ct);
  c.decrypt_block(b);
  check(name + " decrypt", b == pt);
}

}  // namespace

int main() {
  kat("threefish256", Variant::TF256,
      "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F",
      "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
      "E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF");

  kat("threefish512", Variant::TF512,
      "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F"
      "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F",
      "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"
      "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
      "E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779"
      "272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D");

  kat("threefish1024", Variant::TF1024,
      "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F"
      "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F"
      "505152535455565758595A5B5C5D5E5F6061626364656667 68696A6B6C6D6E6F"
      "707172737475767778797A7B7C7D7E7F8081828384858687 88898A8B8C8D8E8F",
      "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"
      "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"
      "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0"
      "9F9E9D9C9B9A99989796959493929190 8F8E8D8C8B8A89888786858483828180",
      "A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C"
      "94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD"
      "8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8"
      "3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE");

  // CTR self-consistency (no official vectors): the first keystream block must
  // equal encrypt_block(iv), and apply-twice must round-trip at an awkward length.
  {
    Bytes key(32, 0x11), tweak(16, 0x00), iv(32, 0x22);
    Threefish c(Variant::TF256, key, tweak);
    Bytes zero(32, 0x00);
    c.ctr_apply(iv, zero);
    Bytes ks = iv;
    c.encrypt_block(ks);
    check("ctr keystream block 0 == encrypt(iv)", zero == ks);

    Bytes msg(200);
    for (int i = 0; i < 200; ++i) msg[i] = static_cast<std::uint8_t>(i);
    Bytes orig = msg;
    c.ctr_apply(iv, msg);
    c.ctr_apply(iv, msg);
    check("ctr round-trips at 200 bytes", msg == orig);
  }

  if (failures == 0) {
    std::puts("\nall passed");
    return 0;
  }
  std::printf("\n%d FAILED\n", failures);
  return 1;
}

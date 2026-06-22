// Tests for the C++ port. Currently: Threefish known-answer vectors (official
// Crypto++ threefish.txt values) and CTR self-consistency. A plain assertion
// harness, exiting non-zero on any failure.
#include "dorado/threefish.hpp"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

#include "dorado/blake3.hpp"
#include "dorado/engine.hpp"
#include "dorado/kdf.hpp"
#include "dorado/mac.hpp"
#include "dorado/sha256.hpp"
#include "dorado/skein.hpp"

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

std::string to_hex(std::span<const std::uint8_t> b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::uint8_t x : b) {
    s += d[x >> 4];
    s += d[x & 0xf];
  }
  return s;
}

// Official BLAKE3 test-vector input convention: byte i = i mod 251.
Bytes seq(std::size_t n) {
  Bytes b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i % 251);
  return b;
}

Bytes ascii(const std::string& s) { return Bytes(s.begin(), s.end()); }

Bytes read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
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

  // Skein-512 (Rust reference digests).
  check("skein512-256 empty",
        to_hex(dorado::skein::hash(32, Bytes{})) ==
            "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621");
  check("skein512-256 abc",
        to_hex(dorado::skein::hash(32, ascii("abc"))) ==
            "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527");
  check("skein512-256 a*100",
        to_hex(dorado::skein::hash(32, Bytes(100, 0x61))) ==
            "933bd28877ef7215ae7d4fd99da95a995cd5555077526c3bc395ad1f1d6bb0fa");
  check("skein512-512 abc",
        to_hex(dorado::skein::hash(64, ascii("abc"))) ==
            "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f938"
            "93ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75");

  // Incremental Skein matches the one-shot at any chunking (gyotaku streaming).
  {
    Bytes msg = seq(700);
    std::string one = to_hex(dorado::skein::hash(32, msg));
    std::size_t steps[] = {1, 7, 63, 64, 65, 200, 700};
    bool ok = true;
    for (std::size_t step : steps) {
      dorado::skein::Hasher h(32);
      for (std::size_t i = 0; i < msg.size(); i += step)
        h.update(std::span<const std::uint8_t>(msg.data() + i, std::min(step, msg.size() - i)));
      if (to_hex(h.finalize()) != one) ok = false;
    }
    check("skein incremental == one-shot", ok);
  }

  // BLAKE3 (Rust reference + official vectors).
  check("blake3 empty",
        to_hex(dorado::blake3::hash(32, Bytes{})) ==
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  check("blake3 abc",
        to_hex(dorado::blake3::hash(32, ascii("abc"))) ==
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
  check("blake3 1024 (one chunk)",
        to_hex(dorado::blake3::hash(32, seq(1024))) ==
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7");
  check("blake3 1025 (parent node)",
        to_hex(dorado::blake3::hash(32, seq(1025))) ==
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444");
  check("blake3 abc XOF 64",
        to_hex(dorado::blake3::hash(64, ascii("abc"))) ==
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
            "1fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0b");
  {
    Bytes key(32);
    for (int i = 0; i < 32; ++i) key[i] = static_cast<std::uint8_t>(i);
    check("blake3 keyed mac",
          to_hex(dorado::blake3::keyed_mac(key, 32, ascii("abc"))) ==
              "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532");
  }

  // SHA-256 (FIPS) and HMAC-SHA256 (RFC 4231).
  check("sha256 empty",
        to_hex(dorado::sha256::hash(Bytes{})) ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("sha256 abc",
        to_hex(dorado::sha256::hash(ascii("abc"))) ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("sha256 56-byte",
        to_hex(dorado::sha256::hash(
            ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  check("hmac-sha256 TC1",
        to_hex(dorado::sha256::hmac(Bytes(20, 0x0b), ascii("Hi There"))) ==
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  check("hmac-sha256 TC2",
        to_hex(dorado::sha256::hmac(ascii("Jefe"), ascii("what do ya want for nothing?"))) ==
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  check("hmac-sha256 TC6 (long key)",
        to_hex(dorado::sha256::hmac(
            Bytes(131, 0xaa),
            ascii("Test Using Larger Than Block-Size Key - Hash Key First"))) ==
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

  // KDF delegation (OpenSSL EVP_KDF). scrypt + PBKDF2 vectors from RFC 7914.
  check("scrypt RFC7914 (N=16,r=1,p=1, empty)",
        to_hex(dorado::kdf::derive(dorado::kdf::Scrypt{4, 1, 1}, Bytes{}, Bytes{}, 64)) ==
            "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
            "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
  check("pbkdf2-hmac-sha256 RFC7914 (passwd/salt, c=1)",
        to_hex(dorado::kdf::derive(dorado::kdf::Pbkdf2{1}, ascii("passwd"), ascii("salt"), 64)) ==
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");

  // MAC dispatch: each option yields a 32-byte tag; the three differ.
  {
    Bytes mk(32, 0x5a);
    auto m1 = dorado::mac::tag(dorado::mac::Mac::HmacSha256, mk, ascii("frame"));
    auto m2 = dorado::mac::tag(dorado::mac::Mac::Skein512, mk, ascii("frame"));
    auto m3 = dorado::mac::tag(dorado::mac::Mac::Blake3Keyed, mk, ascii("frame"));
    check("mac tags are 32 bytes and differ",
          m1.size() == 32 && m2.size() == 32 && m3.size() == 32 && m1 != m2 && m2 != m3 && m1 != m3);
  }

  // Container cross-compatibility: decrypt .mahi files produced by the Rust CLI.
  {
    using namespace dorado;
    Bytes pw = ascii("correct horse battery staple");
    Bytes pt1 = ascii("Attack at dawn. Meet by the old oak.");
    auto dec_fix = [&](const std::string& name, const Bytes& expected) {
      auto r = engine::decrypt_password(pw, read_file("tests/fixtures/" + name));
      check("decrypt rust fixture " + name, r.has_value() && *r == expected);
    };
    dec_fix("pbkdf2-skein-256.mahi", pt1);
    dec_fix("scrypt-hmac-256.mahi", pt1);
    dec_fix("argon2-blake3-256.mahi", pt1);
    dec_fix("pbkdf2-skein-512.mahi", pt1);
    dec_fix("labeled.mahi", pt1);
    dec_fix("multichunk.mahi", seq(3000));

    Bytes fix = read_file("tests/fixtures/pbkdf2-skein-256.mahi");
    check("wrong password rejected", !engine::decrypt_password(ascii("wrong"), fix).has_value());
    Bytes bad = fix;
    bad.back() ^= 1;
    check("tampered tag rejected", !engine::decrypt_password(pw, bad).has_value());

    // Round-trips (fast KDF) across variants, MACs, chunk sizes, and empty input.
    engine::Options o;
    o.kdf = kdf::Pbkdf2{1000};
    Bytes salt(16, 1), tweak(16, 2), iv32(32, 3);
    auto rt = [&](const std::string& nm, engine::Options opts, const Bytes& iv, const Bytes& msg) {
      auto c = engine::encrypt_password_with(opts, salt, tweak, iv, pw, msg);
      auto d = engine::decrypt_password(pw, c);
      check("round-trip " + nm, d.has_value() && *d == msg);
    };
    rt("pbkdf2/skein/256", o, iv32, pt1);
    {
      auto h = o; h.mac = mac::Mac::HmacSha256; rt("hmac-sha256", h, iv32, pt1);
    }
    {
      auto b = o; b.mac = mac::Mac::Blake3Keyed; rt("blake3-keyed", b, iv32, pt1);
    }
    {
      auto v = o; v.variant = Variant::TF512; rt("variant-512", v, Bytes(64, 3), pt1);
    }
    {
      auto m = o; m.chunk_size = 64; rt("multi-frame", m, iv32, seq(200));
    }
    rt("empty plaintext", o, iv32, Bytes{});
  }

  if (failures == 0) {
    std::puts("\nall passed");
    return 0;
  }
  std::printf("\n%d FAILED\n", failures);
  return 1;
}

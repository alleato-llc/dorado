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
#include "dorado/format.hpp"
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

  // Raw-key authenticated CTR (encrypt-then-MAC, caller-supplied key, no
  // password/KDF): known-answer vectors from docs/fixtures/raw-authenticated.md,
  // generated from and verified against the Rust reference. Each is checked in
  // both directions: encrypt(plaintext) must equal the given ciphertext
  // byte-for-byte, and decrypt(ciphertext) must equal the given plaintext.
  {
    using namespace dorado;

    auto kat_raw_auth = [&](const std::string& name, Variant v, mac::Mac m,
                            std::uint32_t chunk_size, const std::string& keyh,
                            const std::string& ivh, const std::string& tweakh,
                            const std::string& pth, const std::string& cth) {
      Bytes key = unhex(keyh), iv = unhex(ivh), tweak = unhex(tweakh);
      Bytes pt = unhex(pth), ct = unhex(cth);
      auto enc = engine::encrypt_raw_authenticated(v, key, tweak, iv, m, chunk_size, pt);
      check(name + " encrypt matches KAT ciphertext", enc.has_value() && *enc == ct);
      auto dec = engine::decrypt_raw_authenticated(v, key, tweak, iv, m, chunk_size, ct);
      check(name + " decrypt matches KAT plaintext", dec.has_value() && *dec == pt);
    };

    kat_raw_auth(
        "t256_skein_single", Variant::TF256, mac::Mac::Skein512, 64 * 1024,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f"
        "6e206163726f7373206c616e677561676573",
        "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab"
        "167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc10"
        "50620de95d5ba50e545621");

    kat_raw_auth(
        "t256_hmac_single", Variant::TF256, mac::Mac::HmacSha256, 64 * 1024,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f"
        "6e206163726f7373206c616e677561676573",
        "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab"
        "167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8968381b4daded95b311377792e768eee91a63e2346b5"
        "85ac3eda337afd6ed6dfff");

    kat_raw_auth(
        "t256_blake3_single", Variant::TF256, mac::Mac::Blake3Keyed, 64 * 1024,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f"
        "6e206163726f7373206c616e677561676573",
        "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab"
        "167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a0dd0de969ab2bf00e7d04304"
        "b45fb53984b5e29deb9834");

    kat_raw_auth(
        "t512_skein_single", Variant::TF512, mac::Mac::Skein512, 64 * 1024,
        "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "1111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
        "0202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f"
        "6e206163726f7373206c616e677561676573",
        "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7ea842953feb5e"
        "bf6aec6b95d17c646a8294b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a8be5fd71b60863900177af52"
        "c649ede00952bde11f1394");

    kat_raw_auth(
        "t1024_skein_single", Variant::TF1024, mac::Mac::Skein512, 64 * 1024,
        "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        "11111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
        "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
        "02020202020202020202020202020202020202020202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f"
        "6e206163726f7373206c616e677561676573",
        "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85cd899f2a52b0"
        "05a0fb1105fe6706ceb7f937573662a11b14b53c939c8ade26889e72113babe3236093b8855432a67c45888b"
        "131be41f72cd890a724f0f");

    kat_raw_auth(
        "t256_skein_multichunk", Variant::TF256, mac::Mac::Skein512, 1024,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "00000000000000000000000000000000",
        "61206c6f6e676572207061796c6f6164206d65616e7420746f207370616e206d756c7469706c65206f6e652d"
        "6b696c6f627974652061757468656e74696361746564206368756e6b7320736f207468652063726f73732d6c"
        "616e6775616765206669787475726520616c736f206578657263697365732074686520636f6e74696e756f75"
        "7320636f756e74657220616e64207065722d6672616d652074616767696e67206163726f7373206368756e6b"
        "20626f756e6461726965732c206e6f74206a75737420612073696e676c65206672616d652e20787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
        "787878787878",
        "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f834310c46654feabc"
        "437288741b5f16b5ff8bab79018d524a3a5bc2f307b486959bdb2b43f608b3a624af1d302506d312ff8c536e"
        "ee10f553ab87e39697249ea5f92050c9ee832a8c8c2d7e4dffba0d5b3650a65d4ec8ef92c6ec60d2030c334e"
        "56e091654db2e1ad8e3cbc921f7092bc34afc8d41226526e31b1da8240da06169ef5643695b82247984b334e"
        "4842a34b88789ff0886098e002521245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e0de9fd48"
        "10f7077c85a8ac7dd49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb62571"
        "79d883d55cf7b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbdf9d79833"
        "8cf01a20326fc4c4d9e0ce7d874cd0f6b5bc493dcfaac173f8259f597a1d28c72e92e2b47a7573857e0dd47b"
        "1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334cc319ab9d06830edccd3bca5ef2e69769a4d2"
        "a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6684a2ef8596c0cf60ba76834ce054fb4f7e524df218c"
        "21c2f552f74e445efbbc24c8b29df788c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a6"
        "9ca4c0f8b111d5213ef4d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd01033492838006045"
        "3213fde390d7d1b36f0f34242b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0d73b"
        "a734da002a4c1fdf9613c25556ed9cb350f1d17a863ddb72a13688f51e7e56f9f6d97fcf1b7f050c4a5f45c0"
        "760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229fd9db1b55dad18a30bc67f3b4670a"
        "35b9c17884feb94f6c7b1183faadb7c60768c34e098754d59ce4b057249e5a7e0fc37a84925d8582a996e3ff"
        "38a3e844711f444a8ad1bbcda549b9d3b3d1f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb3"
        "5bccb5bc5b16053506d66c0171417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e09"
        "0a1442f3a99b46ffcb2db05ae459912ace292e382feddede89ce478b2f09072e8415442d5208e7be684406bc"
        "d8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4354275ac62acc6e797e78c6255fc4aa5"
        "00776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3368d45913b2e1cac5e4b6c6c"
        "790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f6fab39d77d8da052a1aec80b115391f71747"
        "5e9f8ab01ca3a2e7f4ed45e15cb8590c01f6274aae9b75e3852fce44b07f41bfe18777395112bbafbfab1be7"
        "2df1be7a16e502d3385ff547f083bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a416"
        "73617ea43d010000018657d51b2abd9a7809306c46b7c1020a729dd1efddc182b7412e45fae64f45b3e33ad6"
        "440f1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014fa545baa6a184836a0827"
        "98c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e077b1a2ded34f9e30eea3"
        "32309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399ebd1c4407432af717dd7b949f8eee02c"
        "f4dca067b4b6cd7f50dd53b8bff3e35af9352d0d62b3ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f6"
        "82ff312690bf64c277bad2ab306931e97e23dd5790127921af7d16617456c585b835117b08621c40dddd3892"
        "9d0728da224e31dd1d2d5461b2ce6e162f41436c92b5515223aa3f9572ab9ede606fb0c2c94545cc6221179a"
        "a6c11508e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9bdd861c7"
        "1319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb886e7412cd913745"
        "1c75ace33797024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c4309170d8192");

    // -- Behavioral properties (not fixed vectors), using the t256_skein_single
    // parameters --
    Bytes base_key = unhex("1111111111111111111111111111111111111111111111111111111111111111");
    Bytes base_iv = unhex("0202020202020202020202020202020202020202020202020202020202020202");
    Bytes base_tweak = unhex("00000000000000000000000000000000");
    Bytes base_pt = unhex("65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573");
    Bytes base_ct = unhex("010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621");
    const std::uint32_t base_chunk = 64 * 1024;

    // Tamper detection: flip a single ciphertext byte (inside the tag), decrypt
    // must fail, never produce garbage or partial plaintext.
    {
      Bytes tampered = base_ct;
      tampered.back() ^= 1;
      auto r = engine::decrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                base_iv, mac::Mac::Skein512, base_chunk,
                                                tampered);
      check("raw-authenticated: tampered tag rejected", !r.has_value());
    }
    {
      Bytes tampered = base_ct;
      tampered[10] ^= 1;  // inside the ciphertext, not the tag
      auto r = engine::decrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                base_iv, mac::Mac::Skein512, base_chunk,
                                                tampered);
      check("raw-authenticated: tampered ciphertext rejected", !r.has_value());
    }

    // Wrong key: decrypting with a different key must fail.
    {
      Bytes wrong_key = base_key;
      wrong_key[0] ^= 1;
      auto r = engine::decrypt_raw_authenticated(Variant::TF256, wrong_key, base_tweak,
                                                base_iv, mac::Mac::Skein512, base_chunk,
                                                base_ct);
      check("raw-authenticated: wrong key rejected", !r.has_value());
    }

    // Mismatched tweak or IV, ciphertext/tag held fixed: the tweak and IV are
    // bound into frame 0's AAD, not just used for the keystream, so swapping
    // either alone must fail rather than silently produce different plaintext.
    {
      Bytes wrong_tweak = base_tweak;
      wrong_tweak[0] ^= 1;
      auto r = engine::decrypt_raw_authenticated(Variant::TF256, base_key, wrong_tweak,
                                                base_iv, mac::Mac::Skein512, base_chunk,
                                                base_ct);
      check("raw-authenticated: mismatched tweak rejected", !r.has_value());
    }
    {
      Bytes wrong_iv = base_iv;
      wrong_iv[0] ^= 1;
      auto r = engine::decrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                wrong_iv, mac::Mac::Skein512, base_chunk,
                                                base_ct);
      check("raw-authenticated: mismatched iv rejected", !r.has_value());
    }

    // Every MAC option round-trips and rejects tampering.
    for (mac::Mac m : {mac::Mac::Skein512, mac::Mac::HmacSha256, mac::Mac::Blake3Keyed}) {
      auto enc = engine::encrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                  base_iv, m, base_chunk, base_pt);
      bool round_trip_ok = false;
      if (enc.has_value()) {
        auto dec = engine::decrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                    base_iv, m, base_chunk, *enc);
        round_trip_ok = dec.has_value() && *dec == base_pt;
      }
      check("raw-authenticated: mac " + std::to_string(int(mac::mac_id(m))) + " round-trips",
            round_trip_ok);

      if (!enc.has_value()) continue;
      Bytes tampered = *enc;
      tampered.back() ^= 1;
      auto bad = engine::decrypt_raw_authenticated(Variant::TF256, base_key, base_tweak,
                                                  base_iv, m, base_chunk, tampered);
      check("raw-authenticated: mac " + std::to_string(int(mac::mac_id(m))) +
                " rejects tampering",
            !bad.has_value());
    }

    // Round-trip with an arbitrary key/iv for a non-256 variant (T512), with a
    // multi-frame payload, independent of the fixed KAT vectors above.
    {
      Bytes key512(64);
      for (int i = 0; i < 64; ++i) key512[i] = static_cast<std::uint8_t>(i * 3 + 7);
      Bytes iv512(64, 0x5a);
      Bytes tweak2(16, 0x9c);
      Bytes msg = seq(3000);
      auto enc = engine::encrypt_raw_authenticated(Variant::TF512, key512, tweak2, iv512,
                                                  mac::Mac::Skein512, 512, msg);
      bool ok = false;
      if (enc.has_value()) {
        auto dec = engine::decrypt_raw_authenticated(Variant::TF512, key512, tweak2, iv512,
                                                    mac::Mac::Skein512, 512, *enc);
        ok = dec.has_value() && *dec == msg;
      }
      check("raw-authenticated: T512 arbitrary key/iv multi-frame round-trip", ok);
    }
  }

  // Key-based KDF (derive_from_key): all six known-answer vectors from
  // docs/fixtures/derive-from-key.md (generated by the Rust reference), plus
  // the determinism/domain-separation properties the Rust kdf tests check.
  {
    using namespace dorado;
    Bytes key32 = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    Bytes key16 = unhex("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");

    auto kat_kdf = [&](const std::string& name, kdf::KdfPrf prf, const Bytes& key,
                       std::string_view domain, std::size_t out_len, const std::string& outh) {
      auto r = kdf::derive_from_key_with(prf, key, domain, out_len);
      check("derive_from_key " + name, r.has_value() && to_hex(*r) == outh);
    };
    kat_kdf("skein_32key_enc_32out", kdf::KdfPrf::Skein512, key32, "dorado/fixture/enc", 32,
            "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6");
    kat_kdf("skein_32key_mac_64out", kdf::KdfPrf::Skein512, key32, "dorado/fixture/mac", 64,
            "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40e"
            "f227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6");
    kat_kdf("skein_16key_enc_32out", kdf::KdfPrf::Skein512, key16, "dorado/fixture/enc", 32,
            "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4");
    kat_kdf("skein_32key_empty_domain_32out", kdf::KdfPrf::Skein512, key32, "", 32,
            "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99");
    kat_kdf("blake3_32key_enc_32out", kdf::KdfPrf::Blake3, key32, "dorado/fixture/enc", 32,
            "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d");
    kat_kdf("blake3_32key_mac_64out", kdf::KdfPrf::Blake3, key32, "dorado/fixture/mac", 64,
            "ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa"
            "9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290");

    // The default form is defined as the Skein-512 case: byte-for-byte equal,
    // so the default is never a silent change.
    check("derive_from_key default == Skein512 PRF",
          kdf::derive_from_key(key32, "dorado/fixture/enc", 32) ==
              *kdf::derive_from_key_with(kdf::KdfPrf::Skein512, key32, "dorado/fixture/enc", 32));

    // Deterministic; different domain or different key gives unrelated bytes.
    Bytes master(32, 0x42);
    Bytes a = kdf::derive_from_key(master, "myapp/index", 32);
    check("derive_from_key deterministic", a == kdf::derive_from_key(master, "myapp/index", 32));
    check("derive_from_key domain-separated", a != kdf::derive_from_key(master, "myapp/data", 32));
    check("derive_from_key key-separated",
          a != kdf::derive_from_key(Bytes(32, 0x43), "myapp/index", 32));
    check("derive_from_key child != master", a != master);

    // Skein's output length is part of its config: a longer output is a
    // different hash, not an extension of the shorter one.
    Bytes long_out = kdf::derive_from_key(master, "myapp/index", 128);
    check("derive_from_key skein length is bound in",
          !std::equal(a.begin(), a.end(), long_out.begin()));

    // BLAKE3 is an XOF: a shorter output is the prefix of a longer one.
    auto b3_short = kdf::derive_from_key_with(kdf::KdfPrf::Blake3, master, "myapp/index", 32);
    auto b3_long = kdf::derive_from_key_with(kdf::KdfPrf::Blake3, master, "myapp/index", 128);
    check("derive_from_key blake3 xof prefix",
          b3_short.has_value() && b3_long.has_value() &&
              std::equal(b3_short->begin(), b3_short->end(), b3_long->begin()));

    // The two PRFs are independent functions and must not coincide.
    check("derive_from_key blake3 != skein",
          b3_short.has_value() && *b3_short != kdf::derive_from_key(master, "myapp/index", 32));

    // BLAKE3's keyed mode is defined only for a 32-byte key.
    check("derive_from_key blake3 rejects non-32-byte key",
          !kdf::derive_from_key_with(kdf::KdfPrf::Blake3, key16, "myapp/index", 32).has_value());
  }

  // KDF cost validation: costs read from an untrusted header are bounded before
  // any derivation. Each individual knob has its own bound.
  {
    using namespace dorado;
    auto ok = [](const kdf::Kdf& k) { return kdf::validate(k).has_value(); };
    check("validate accepts argon2 defaults", ok(kdf::Argon2id{64 * 1024, 3, 1}));
    check("validate accepts scrypt defaults", ok(kdf::Scrypt{15, 8, 1}));
    check("validate accepts pbkdf2 default", ok(kdf::Pbkdf2{600000}));
    check("validate rejects argon2 m_cost > 2^21", !ok(kdf::Argon2id{(1u << 21) + 1, 3, 1}));
    check("validate rejects argon2 t_cost > 64", !ok(kdf::Argon2id{1024, 65, 1}));
    check("validate rejects argon2 p_cost > 16", !ok(kdf::Argon2id{1024, 3, 17}));
    check("validate rejects scrypt log_n > 21", !ok(kdf::Scrypt{22, 8, 1}));
    check("validate rejects scrypt r > 32", !ok(kdf::Scrypt{15, 33, 1}));
    check("validate rejects scrypt p > 16", !ok(kdf::Scrypt{15, 8, 17}));
    check("validate rejects pbkdf2 rounds == 0", !ok(kdf::Pbkdf2{0}));
    check("validate rejects pbkdf2 rounds > 50e6", !ok(kdf::Pbkdf2{50000001}));

    // A crafted header carrying hostile costs (or a hostile chunk size) is
    // rejected cleanly before any expensive derivation or large allocation, and
    // distinctly from an authentication failure.
    auto hostile = [&](const std::string& name, const kdf::Kdf& k, std::uint32_t chunk_size) {
      format::Header h{4, Variant::TF256, k,          mac::Mac::Skein512, chunk_size,
                       Bytes(16, 1),      Bytes(16, 2), Bytes(32, 3),     {}};
      auto container = format::serialize(h);
      auto r = engine::decrypt_password(ascii("pw"), container);
      check(name, !r.has_value() && r.error().find("authentication") == std::string::npos);
    };
    hostile("hostile argon2 header rejected before derivation", kdf::Argon2id{1u << 30, 3, 1},
            65536);
    hostile("hostile scrypt header rejected before derivation", kdf::Scrypt{40, 8, 1}, 65536);
    hostile("hostile pbkdf2 header rejected before derivation", kdf::Pbkdf2{0xffffffffu}, 65536);
    hostile("oversized header chunk size rejected", kdf::Pbkdf2{1000},
            engine::kDefaultMaxChunkBytes + 32);
    hostile("zero header chunk size rejected", kdf::Pbkdf2{1000}, 0);
    hostile("non-block-multiple header chunk size rejected", kdf::Pbkdf2{1000}, 65537);
  }

  // Chunk-size cap resolution (pure helper mirroring Rust's chunk_cap_from) and
  // its enforcement on the raw-authenticated decrypt path.
  {
    using namespace dorado;
    check("chunk cap default when unset",
          engine::chunk_cap_from(std::nullopt) == engine::kDefaultMaxChunkBytes);
    check("chunk cap explicit override", engine::chunk_cap_from("1048576") == 1048576u);
    check("chunk cap trims whitespace", engine::chunk_cap_from(" 4096 ") == 4096u);
    check("chunk cap clamps zero up to 1", engine::chunk_cap_from("0") == 1u);
    check("chunk cap clamps to the hard ceiling",
          engine::chunk_cap_from("4294967295") == engine::kMaxChunkBytes);
    check("chunk cap garbage falls back to default",
          engine::chunk_cap_from("banana") == engine::kDefaultMaxChunkBytes);
    check("chunk cap overflow falls back to default",
          engine::chunk_cap_from("9999999999") == engine::kDefaultMaxChunkBytes);

    // The raw-authenticated decrypt path bounds the caller/relayed chunk size
    // by the cap before any allocation (the cap is enforced on decrypt,
    // matching the Rust reference).
    auto r = engine::decrypt_raw_authenticated(Variant::TF256, Bytes(32, 1), Bytes(16, 0),
                                               Bytes(32, 2), mac::Mac::Skein512,
                                               engine::kDefaultMaxChunkBytes + 32, Bytes{});
    check("raw-authenticated decrypt rejects chunk size over cap",
          !r.has_value() && r.error().find("exceeds") != std::string::npos);
  }

  if (failures == 0) {
    std::puts("\nall passed");
    return 0;
  }
  std::printf("\n%d FAILED\n", failures);
  return 1;
}

/* Test harness for the C port: primitive KATs (official + Rust-baked vectors), the
 * construction's round-trips and security properties, and cross-compat fixtures
 * produced by the Rust reference. Returns non-zero if any check fails. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dorado/blake3.h"
#include "dorado/engine.h"
#include "dorado/skein.h"
#include "dorado/threefish.h"

/* Pure chunk-cap parser, declared in the internal src/format.h (not a public
 * header); declared here so the test can exercise it without -Isrc. Kept in sync
 * with format.h. */
#include <stdint.h>
uint32_t dorado_chunk_cap_from(const char *s);
#define TEST_DEFAULT_MAX_CHUNK (64u * 1024 * 1024)
#define TEST_HARD_MAX_CHUNK (1u << 30)

/* Internal KDF cost-parameter validation, declared in the internal src/kdf.h (not
 * a public header); declared here so the test can exercise it without -Isrc. Kept
 * in sync with kdf.h. */
const char *dorado_kdf_validate(const dorado_kdf_params *p);

static int g_pass = 0, g_fail = 0;

static int hv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t unhex(const char *s, uint8_t *out) {
    size_t n = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ' ') continue;
        out[n++] = (uint8_t)((hv(p[0]) << 4) | hv(p[1]));
        p++;
    }
    return n;
}
static void tohex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + i * 2, "%02x", b[i]);
}

static void check(int ok, const char *name) {
    if (ok) {
        g_pass++;
    } else {
        g_fail++;
        printf("FAIL: %s\n", name);
    }
}

static int hash_eq(const uint8_t *got, size_t n, const char *expect_hex) {
    char h[256];
    tohex(got, n, h);
    return strcmp(h, expect_hex) == 0;
}

static void test_threefish(void) {
    uint8_t key[128], tw[16], pt[128], ct[128], got[128];
    unhex("000102030405060708090A0B0C0D0E0F", tw);
    unhex("101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F", key);
    unhex("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0", pt);
    dorado_threefish tf;
    dorado_threefish_init(&tf, DORADO_T256, key, tw);
    dorado_threefish_encrypt_block(&tf, ct, pt);
    check(hash_eq(ct, 32, "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df"), "threefish256 KAT");
    dorado_threefish_decrypt_block(&tf, got, ct);
    check(memcmp(got, pt, 32) == 0, "threefish256 round-trip");
}

static void seq(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)i;
}

static void test_hashes(void) {
    uint8_t out[64], buf[3000], key[32];
    dorado_skein512_hash(64, (const uint8_t *)"", 0, out);
    check(hash_eq(out, 64,
                  "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
                  "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"),
          "skein512 empty");
    dorado_skein512_hash(32, (const uint8_t *)"abc", 3, out);
    check(hash_eq(out, 32, "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"), "skein256 abc");
    seq(buf, 500);
    dorado_skein512_hash(32, buf, 500, out);
    check(hash_eq(out, 32, "15096f2f503dce8eab3ab3ac80d840dafdd8001ca1737fab69b717475b4abdaf"), "skein256 500");
    memset(key, 0x9c, 32);
    dorado_skein512_mac(key, 32, 32, (const uint8_t *)"authenticate me", 15, out);
    check(hash_eq(out, 32, "8b0865bcabf2dec950b2178b5127e88914d039a0681339e5d10e06d95bad12b3"), "skein mac");

    dorado_blake3_hash(32, (const uint8_t *)"", 0, out);
    check(hash_eq(out, 32, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"), "blake3 empty");
    seq(buf, 3000);
    dorado_blake3_hash(32, buf, 3000, out);
    check(hash_eq(out, 32, "6c943946a70794f2e14c785d5ee88d300d5f9b91d1b4ef88302974ac4b069052"), "blake3 3000 (tree)");
    dorado_blake3_keyed_mac(key, 32, (const uint8_t *)"authenticate me", 15, out);
    check(hash_eq(out, 32, "e8a84781007d67df2b0de8cf1d0c48b0fee97a0f9744ba5b325c1aac2d670a08"), "blake3 keyed mac");
}

static dorado_options opts(int variant, dorado_kdf_params kdf, int mac) {
    dorado_options o = {0};
    o.variant = variant;
    o.kdf = kdf;
    o.mac = mac;
    o.chunk_size = DORADO_DEFAULT_CHUNK_BYTES;
    return o;
}

static void test_engine(void) {
    const uint8_t *pw = (const uint8_t *)"correct horse battery staple";
    size_t pwl = strlen((const char *)pw);
    const uint8_t *pt = (const uint8_t *)"the quick brown fox jumps over the lazy dog";
    size_t ptl = strlen((const char *)pt);

    int variants[3] = {DORADO_T256, DORADO_T512, DORADO_T1024};
    int macs[3] = {DORADO_MAC_SKEIN, DORADO_MAC_HMAC, DORADO_MAC_BLAKE3};
    dorado_kdf_params kdfs[3] = {dorado_kdf_argon2id(8 * 1024, 1, 1), dorado_kdf_scrypt(14, 8, 1),
                                 dorado_kdf_pbkdf2(20000)};
    int all_ok = 1;
    for (int v = 0; v < 3; v++)
        for (int k = 0; k < 3; k++)
            for (int m = 0; m < 3; m++) {
                dorado_options o = opts(variants[v], kdfs[k], macs[m]);
                uint8_t *ct = NULL, *back = NULL;
                size_t ctl = 0, bl = 0;
                const char *e1 = dorado_encrypt_password(pw, pwl, &o, pt, ptl, &ct, &ctl);
                const char *e2 = e1 ? "skip" : dorado_decrypt_password(pw, pwl, NULL, 0, ct, ctl, &back, &bl);
                if (e1 || e2 || bl != ptl || memcmp(back, pt, ptl) != 0) all_ok = 0;
                free(ct);
                free(back);
            }
    check(all_ok, "round-trip every variant/kdf/mac");

    dorado_options o = opts(DORADO_T256, dorado_kdf_pbkdf2(20000), DORADO_MAC_SKEIN);

    /* empty plaintext */
    uint8_t *ct = NULL, *back = NULL;
    size_t ctl = 0, bl = 0;
    dorado_encrypt_password(pw, pwl, &o, (const uint8_t *)"", 0, &ct, &ctl);
    const char *e = dorado_decrypt_password(pw, pwl, NULL, 0, ct, ctl, &back, &bl);
    check(!e && bl == 0, "empty plaintext round-trip");
    free(back); /* an empty output still hands the caller a (1-byte) buffer */
    back = NULL;

    /* wrong password: classifies as auth by pointer identity */
    check(dorado_decrypt_password((const uint8_t *)"wrong", 5, NULL, 0, ct, ctl, &back, &bl) == dorado_err_auth,
          "wrong password -> dorado_err_auth");
    /* tampering: indistinguishable from wrong password (same sentinel) */
    ct[ctl - 1] ^= 1;
    check(dorado_decrypt_password(pw, pwl, NULL, 0, ct, ctl, &back, &bl) == dorado_err_auth,
          "tampering -> dorado_err_auth (merged)");
    ct[ctl - 1] ^= 1;
    /* truncation: a short/malformed frame is the malformed class */
    check(dorado_decrypt_password(pw, pwl, NULL, 0, ct, ctl - 8, &back, &bl) == dorado_err_malformed,
          "truncation -> dorado_err_malformed");
    free(ct);

    /* bad magic: malformed class */
    dorado_container_info info;
    check(dorado_inspect((const uint8_t *)"XXXX\x00\x00\x00\x00", 8, &info) == dorado_err_malformed,
          "bad magic -> dorado_err_malformed");

    /* label binding */
    dorado_options ol = opts(DORADO_T256, dorado_kdf_pbkdf2(20000), DORADO_MAC_SKEIN);
    ol.label = (const uint8_t *)"demo-context";
    ol.label_len = 12;
    dorado_encrypt_password(pw, pwl, &ol, pt, ptl, &ct, &ctl);
    e = dorado_decrypt_password(pw, pwl, (const uint8_t *)"demo-context", 12, ct, ctl, &back, &bl);
    check(!e && bl == ptl, "label match decrypts");
    free(back);
    check(dorado_decrypt_password(pw, pwl, (const uint8_t *)"other", 5, ct, ctl, &back, &bl) != NULL, "label mismatch");
    check(!dorado_inspect(ct, ctl, &info) && info.label_len == 12 && memcmp(info.label, "demo-context", 12) == 0,
          "inspect label");
    free(ct);
}

/* Raw-key authenticated mode: known-answer vectors from docs/fixtures/raw-authenticated.md,
 * generated from and verified against the Rust reference. Encrypting the given
 * plaintext with the given key/tweak/iv/mac/chunk_size must produce the given
 * ciphertext byte-for-byte, and decrypting the given ciphertext must produce the
 * given plaintext byte-for-byte. This is the cross-language compatibility proof for
 * the construction (see docs/spec.md's "Raw-key modes" section for the byte-level
 * spec). */
typedef struct {
    const char *name;
    int variant;
    int mac;
    uint32_t chunk_kib;
    const char *key_hex;
    const char *iv_hex;
    const char *tweak_hex;
    const char *pt_hex;
    const char *ct_hex;
} raw_auth_vector;

static const raw_auth_vector RAW_AUTH_VECTORS[] = {
    {"t256_skein_single", DORADO_T256, DORADO_MAC_SKEIN, 64,
     "1111111111111111111111111111111111111111111111111111111111111111",
     "0202020202020202020202020202020202020202020202020202020202020202",
     "00000000000000000000000000000000",
     "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c"
     "616e677561676573",
     "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39b"
     "bd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621"},
    {"t256_hmac_single", DORADO_T256, DORADO_MAC_HMAC, 64,
     "1111111111111111111111111111111111111111111111111111111111111111",
     "0202020202020202020202020202020202020202020202020202020202020202",
     "00000000000000000000000000000000",
     "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c"
     "616e677561676573",
     "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39b"
     "bd7e178d5f5e2054d2fc14b8968381b4daded95b311377792e768eee91a63e2346b585ac3eda337afd6ed6dfff"},
    {"t256_blake3_single", DORADO_T256, DORADO_MAC_BLAKE3, 64,
     "1111111111111111111111111111111111111111111111111111111111111111",
     "0202020202020202020202020202020202020202020202020202020202020202",
     "00000000000000000000000000000000",
     "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c"
     "616e677561676573",
     "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39b"
     "bd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a0dd0de969ab2bf00e7d04304b45fb53984b5e29deb9834"},
    {"t512_skein_single", DORADO_T512, DORADO_MAC_SKEIN, 64,
     "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
     "11111111111111111111",
     "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
     "02020202020202020202",
     "00000000000000000000000000000000",
     "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c"
     "616e677561676573",
     "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7ea842953feb5ebf6aec6b95d17c646a82"
     "94b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a8be5fd71b60863900177af52c649ede00952bde11f1394"},
    {"t1024_skein_single", DORADO_T1024, DORADO_MAC_SKEIN, 64,
     "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
     "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
     "1111111111111111111111111111111111111111",
     "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
     "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
     "0202020202020202020202020202020202020202",
     "00000000000000000000000000000000",
     "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c"
     "616e677561676573",
     "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85cd899f2a52b005a0fb1105fe6706ceb7"
     "f937573662a11b14b53c939c8ade26889e72113babe3236093b8855432a67c45888b131be41f72cd890a724f0f"},
    {"t256_skein_multichunk", DORADO_T256, DORADO_MAC_SKEIN, 1,
     "1111111111111111111111111111111111111111111111111111111111111111",
     "0202020202020202020202020202020202020202020202020202020202020202",
     "00000000000000000000000000000000",
     "61206c6f6e676572207061796c6f6164206d65616e7420746f207370616e206d756c7469706c65206f6e652d6b696c6f627974652061"
     "757468656e74696361746564206368756e6b7320736f207468652063726f73732d6c616e6775616765206669787475726520616c736f"
     "206578657263697365732074686520636f6e74696e756f757320636f756e74657220616e64207065722d6672616d652074616767696e"
     "67206163726f7373206368756e6b20626f756e6461726965732c206e6f74206a75737420612073696e676c65206672616d652e207878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
     "78787878787878787878",
     "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f834310c46654feabc437288741b5f16b5ff8b"
     "ab79018d524a3a5bc2f307b486959bdb2b43f608b3a624af1d302506d312ff8c536eee10f553ab87e39697249ea5f92050c9ee832a8c"
     "8c2d7e4dffba0d5b3650a65d4ec8ef92c6ec60d2030c334e56e091654db2e1ad8e3cbc921f7092bc34afc8d41226526e31b1da8240da"
     "06169ef5643695b82247984b334e4842a34b88789ff0886098e002521245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e"
     "0de9fd4810f7077c85a8ac7dd49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb6257179d883d55cf7"
     "b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbdf9d798338cf01a20326fc4c4d9e0ce7d874cd0f6"
     "b5bc493dcfaac173f8259f597a1d28c72e92e2b47a7573857e0dd47b1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334c"
     "c319ab9d06830edccd3bca5ef2e69769a4d2a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6684a2ef8596c0cf60ba76834ce05"
     "4fb4f7e524df218c21c2f552f74e445efbbc24c8b29df788c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a69ca4"
     "c0f8b111d5213ef4d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd010334928380060453213fde390d7d1b36f0f3424"
     "2b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0d73ba734da002a4c1fdf9613c25556ed9cb350f1d17a863d"
     "db72a13688f51e7e56f9f6d97fcf1b7f050c4a5f45c0760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229fd9db"
     "1b55dad18a30bc67f3b4670a35b9c17884feb94f6c7b1183faadb7c60768c34e098754d59ce4b057249e5a7e0fc37a84925d8582a996"
     "e3ff38a3e844711f444a8ad1bbcda549b9d3b3d1f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb35bccb5bc5b160535"
     "06d66c0171417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e090a1442f3a99b46ffcb2db05ae459912ace29"
     "2e382feddede89ce478b2f09072e8415442d5208e7be684406bcd8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4"
     "354275ac62acc6e797e78c6255fc4aa500776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3368d45913b2e"
     "1cac5e4b6c6c790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f6fab39d77d8da052a1aec80b115391f717475e9f8ab0"
     "1ca3a2e7f4ed45e15cb8590c01f6274aae9b75e3852fce44b07f41bfe18777395112bbafbfab1be72df1be7a16e502d3385ff547f083"
     "bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a41673617ea43d010000018657d51b2abd9a7809306c46b7c102"
     "0a729dd1efddc182b7412e45fae64f45b3e33ad6440f1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014f"
     "a545baa6a184836a082798c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e077b1a2ded34f9e30eea3"
     "32309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399ebd1c4407432af717dd7b949f8eee02cf4dca067b4b6cd7f50dd"
     "53b8bff3e35af9352d0d62b3ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f682ff312690bf64c277bad2ab306931e97e23dd57"
     "90127921af7d16617456c585b835117b08621c40dddd38929d0728da224e31dd1d2d5461b2ce6e162f41436c92b5515223aa3f9572ab"
     "9ede606fb0c2c94545cc6221179aa6c11508e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9"
     "bdd861c71319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb886e7412cd9137451c75ace33797"
     "024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c4309170d8192"},
};
#define RAW_AUTH_VECTOR_COUNT (sizeof RAW_AUTH_VECTORS / sizeof RAW_AUTH_VECTORS[0])

static void run_raw_auth_vector(const raw_auth_vector *v) {
    size_t key_len = strlen(v->key_hex) / 2;
    size_t iv_len = strlen(v->iv_hex) / 2;
    size_t pt_len = strlen(v->pt_hex) / 2;
    size_t ct_len = strlen(v->ct_hex) / 2;
    uint8_t *key = malloc(key_len);
    uint8_t *iv = malloc(iv_len);
    uint8_t tweak[16];
    uint8_t *pt = malloc(pt_len);
    uint8_t *ct_expect = malloc(ct_len);
    unhex(v->key_hex, key);
    unhex(v->iv_hex, iv);
    unhex(v->tweak_hex, tweak);
    unhex(v->pt_hex, pt);
    unhex(v->ct_hex, ct_expect);
    uint32_t chunk_size = v->chunk_kib * 1024u;

    char name[160];
    uint8_t *ct_got = NULL;
    size_t ct_got_len = 0;
    const char *e1 = dorado_encrypt_raw_authenticated(v->variant, key, tweak, iv, v->mac, chunk_size, pt, pt_len,
                                                       &ct_got, &ct_got_len);
    snprintf(name, sizeof name, "raw authenticated KAT %s: encrypt matches", v->name);
    check(!e1 && ct_got_len == ct_len && memcmp(ct_got, ct_expect, ct_len) == 0, name);

    uint8_t *pt_got = NULL;
    size_t pt_got_len = 0;
    const char *e2 = dorado_decrypt_raw_authenticated(v->variant, key, tweak, iv, v->mac, chunk_size, ct_expect,
                                                       ct_len, &pt_got, &pt_got_len);
    snprintf(name, sizeof name, "raw authenticated KAT %s: decrypt matches", v->name);
    check(!e2 && pt_got_len == pt_len && memcmp(pt_got, pt, pt_len) == 0, name);

    free(key);
    free(iv);
    free(pt);
    free(ct_expect);
    free(ct_got);
    free(pt_got);
}

static void test_raw_authenticated_kat(void) {
    for (size_t i = 0; i < RAW_AUTH_VECTOR_COUNT; i++) {
        run_raw_auth_vector(&RAW_AUTH_VECTORS[i]);
    }
}

/* Round-trip and tamper-rejection across every variant x MAC combination (not KAT
 * vectors, just exercising the whole matrix like test_engine does for the password
 * container). */
static void test_raw_authenticated_matrix(void) {
    uint8_t key[128], iv[128], tweak[16];
    memset(tweak, 0x11, sizeof tweak);
    int variants[3] = {DORADO_T256, DORADO_T512, DORADO_T1024};
    int macs[3] = {DORADO_MAC_SKEIN, DORADO_MAC_HMAC, DORADO_MAC_BLAKE3};
    const uint8_t *pt = (const uint8_t *)"raw authenticated mode round-trip across variants and MACs";
    size_t ptl = strlen((const char *)pt);
    int all_ok = 1, all_tamper_ok = 1;
    for (int vi = 0; vi < 3; vi++) {
        int variant = variants[vi];
        int kl = dorado_variant_len(variant);
        for (int i = 0; i < kl; i++) key[i] = (uint8_t)(0x40 + vi * 16 + i);
        for (int i = 0; i < kl; i++) iv[i] = (uint8_t)(0x80 + vi * 16 + i);
        for (int mi = 0; mi < 3; mi++) {
            int mac = macs[mi];
            uint8_t *ct = NULL, *back = NULL;
            size_t ctl = 0, bl = 0;
            const char *e1 = dorado_encrypt_raw_authenticated(variant, key, tweak, iv, mac, 64u * 1024u, pt, ptl,
                                                               &ct, &ctl);
            const char *e2 = e1 ? "skip"
                                 : dorado_decrypt_raw_authenticated(variant, key, tweak, iv, mac, 64u * 1024u, ct,
                                                                     ctl, &back, &bl);
            if (e1 || e2 || bl != ptl || memcmp(back, pt, ptl) != 0) all_ok = 0;
            free(back);
            back = NULL;
            bl = 0;

            if (ct && ctl) {
                ct[ctl - 1] ^= 1;
                const char *e3 = dorado_decrypt_raw_authenticated(variant, key, tweak, iv, mac, 64u * 1024u, ct, ctl,
                                                                   &back, &bl);
                if (e3 != dorado_err_auth) all_tamper_ok = 0;
                free(back);
            }
            free(ct);
        }
    }
    check(all_ok, "raw authenticated: round-trip every variant x mac");
    check(all_tamper_ok, "raw authenticated: tamper -> dorado_err_auth every variant x mac");
}

/* Security properties beyond simple tampering: wrong key, wrong tweak, wrong IV
 * (ciphertext/tag held fixed). The tweak and IV are bound into frame 0's AAD, not
 * just used for the keystream, so swapping either alone must fail rather than
 * silently produce different plaintext. */
static void test_raw_authenticated_security(void) {
    uint8_t key[32], key2[32], iv[32], iv2[32], tweak[16], tweak2[16];
    memset(key, 0x11, sizeof key);
    memset(key2, 0x22, sizeof key2);
    memset(iv, 0x02, sizeof iv);
    memset(iv2, 0x03, sizeof iv2);
    memset(tweak, 0x00, sizeof tweak);
    memset(tweak2, 0x05, sizeof tweak2);
    const uint8_t *pt = (const uint8_t *)"security properties for raw authenticated mode";
    size_t ptl = strlen((const char *)pt);

    uint8_t *ct = NULL, *back = NULL;
    size_t ctl = 0, bl = 0;
    const char *e = dorado_encrypt_raw_authenticated(DORADO_T256, key, tweak, iv, DORADO_MAC_SKEIN, 64u * 1024u, pt,
                                                      ptl, &ct, &ctl);
    check(!e, "raw authenticated: setup encrypt for security tests");

    check(dorado_decrypt_raw_authenticated(DORADO_T256, key2, tweak, iv, DORADO_MAC_SKEIN, 64u * 1024u, ct, ctl,
                                           &back, &bl) == dorado_err_auth,
          "raw authenticated: wrong key -> dorado_err_auth");

    check(dorado_decrypt_raw_authenticated(DORADO_T256, key, tweak2, iv, DORADO_MAC_SKEIN, 64u * 1024u, ct, ctl,
                                           &back, &bl) == dorado_err_auth,
          "raw authenticated: mismatched tweak -> dorado_err_auth");

    check(dorado_decrypt_raw_authenticated(DORADO_T256, key, tweak, iv2, DORADO_MAC_SKEIN, 64u * 1024u, ct, ctl,
                                           &back, &bl) == dorado_err_auth,
          "raw authenticated: mismatched iv -> dorado_err_auth");

    if (ctl > 40) {
        ct[10] ^= 1;
        check(dorado_decrypt_raw_authenticated(DORADO_T256, key, tweak, iv, DORADO_MAC_SKEIN, 64u * 1024u, ct, ctl,
                                               &back, &bl) == dorado_err_auth,
              "raw authenticated: tamper ciphertext byte -> dorado_err_auth");
        ct[10] ^= 1;
    }

    e = dorado_decrypt_raw_authenticated(DORADO_T256, key, tweak, iv, DORADO_MAC_SKEIN, 64u * 1024u, ct, ctl, &back,
                                         &bl);
    check(!e && bl == ptl && memcmp(back, pt, ptl) == 0, "raw authenticated: correct params still round-trip");

    free(ct);
    free(back);
}

/* Key-based derivation (dorado_kdf_derive_from_key): known-answer vectors from
 * docs/fixtures/derive-from-key.md, generated from the Rust reference
 * (dorado-engine's kdf::derive_from_key_with). The construction is one
 * domain-separated keyed hash: out = PRF(key, out_len, "DRDOkdrv" || domain).
 * Library API only; nothing here touches the on-disk container format. */
typedef struct {
    const char *name;
    int prf;
    const char *key_hex;
    const char *domain;
    size_t out_len;
    const char *out_hex;
} derive_key_vector;

static const derive_key_vector DERIVE_KEY_VECTORS[] = {
    {"skein_32key_enc_32out", DORADO_KDF_PRF_SKEIN512,
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "dorado/fixture/enc", 32,
     "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6"},
    {"skein_32key_mac_64out", DORADO_KDF_PRF_SKEIN512,
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "dorado/fixture/mac", 64,
     "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40e"
     "f227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6"},
    {"skein_16key_enc_32out", DORADO_KDF_PRF_SKEIN512, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "dorado/fixture/enc", 32,
     "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4"},
    {"skein_32key_empty_domain_32out", DORADO_KDF_PRF_SKEIN512,
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "", 32,
     "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99"},
    {"blake3_32key_enc_32out", DORADO_KDF_PRF_BLAKE3,
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "dorado/fixture/enc", 32,
     "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d"},
    {"blake3_32key_mac_64out", DORADO_KDF_PRF_BLAKE3,
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "dorado/fixture/mac", 64,
     "ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa"
     "9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290"},
};
#define DERIVE_KEY_VECTOR_COUNT (sizeof DERIVE_KEY_VECTORS / sizeof DERIVE_KEY_VECTORS[0])

static void test_derive_from_key_kat(void) {
    for (size_t i = 0; i < DERIVE_KEY_VECTOR_COUNT; i++) {
        const derive_key_vector *v = &DERIVE_KEY_VECTORS[i];
        uint8_t key[64], out[64];
        size_t key_len = unhex(v->key_hex, key);
        char name[128];
        const char *e = dorado_kdf_derive_from_key_with(v->prf, key, key_len, v->domain, out, v->out_len);
        snprintf(name, sizeof name, "derive-from-key KAT %s", v->name);
        check(!e && hash_eq(out, v->out_len, v->out_hex), name);
        if (v->prf == DORADO_KDF_PRF_SKEIN512) {
            /* The default, PRF-less form is defined as the Skein-512 case and
             * must match the same vectors byte-for-byte. */
            uint8_t out2[64];
            e = dorado_kdf_derive_from_key(key, key_len, v->domain, out2, v->out_len);
            snprintf(name, sizeof name, "derive-from-key KAT %s (default form)", v->name);
            check(!e && memcmp(out2, out, v->out_len) == 0, name);
        }
    }
}

/* Determinism, domain separation, output-length binding, and the BLAKE3 key-length
 * requirement, mirroring the Rust reference's kdf tests. */
static void test_derive_from_key_properties(void) {
    uint8_t master[32], other[32];
    memset(master, 0x42, sizeof master);
    memset(other, 0x43, sizeof other);

    uint8_t a[32], b[32], c[32], d[32];
    check(!dorado_kdf_derive_from_key(master, 32, "myapp/index", a, 32) &&
              !dorado_kdf_derive_from_key(master, 32, "myapp/index", b, 32) && memcmp(a, b, 32) == 0,
          "derive-from-key: same key + domain -> same bytes");
    check(!dorado_kdf_derive_from_key(master, 32, "myapp/data", c, 32) && memcmp(a, c, 32) != 0,
          "derive-from-key: different domain -> different key");
    check(!dorado_kdf_derive_from_key(other, 32, "myapp/index", d, 32) && memcmp(a, d, 32) != 0,
          "derive-from-key: different master -> different key");
    check(memcmp(a, master, 32) != 0 && memcmp(c, master, 32) != 0, "derive-from-key: children never equal master");

    /* Skein's output length is part of its config block, so a longer output is a
     * different configuration, not a prefix extension of the shorter one. */
    uint8_t longer[128];
    check(!dorado_kdf_derive_from_key(master, 32, "myapp/index", longer, 128) && memcmp(a, longer, 32) != 0,
          "derive-from-key: skein output length is bound, not a truncation");

    /* BLAKE3 PRF: deterministic, domain separated, and an independent function
     * from the Skein fan-out (same key/domain must not coincide). */
    uint8_t ba[32], bb[32], bc[32];
    check(!dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_BLAKE3, master, 32, "myapp/index", ba, 32) &&
              !dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_BLAKE3, master, 32, "myapp/index", bb, 32) &&
              memcmp(ba, bb, 32) == 0,
          "derive-from-key blake3: same key + domain -> same bytes");
    check(!dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_BLAKE3, master, 32, "myapp/data", bc, 32) &&
              memcmp(ba, bc, 32) != 0,
          "derive-from-key blake3: different domain -> different key");
    check(memcmp(ba, master, 32) != 0, "derive-from-key blake3: child never equals master");
    check(memcmp(ba, a, 32) != 0, "derive-from-key: blake3 and skein fan-outs differ");

    /* BLAKE3 is an XOF: a shorter output is the prefix of a longer one. */
    uint8_t blong[128];
    check(!dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_BLAKE3, master, 32, "myapp/index", blong, 128) &&
              memcmp(ba, blong, 32) == 0,
          "derive-from-key blake3: XOF prefix property");

    /* BLAKE3's keyed mode is defined only for a 32-byte key; other lengths are
     * the params class. So is an unknown PRF. */
    uint8_t out[32];
    check(dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_BLAKE3, master, 16, "myapp/index", out, 32) ==
              dorado_err_params,
          "derive-from-key blake3: non-32-byte key -> dorado_err_params");
    check(dorado_kdf_derive_from_key_with(99, master, 32, "myapp/index", out, 32) == dorado_err_params,
          "derive-from-key: unknown prf -> dorado_err_params");
}

/* KDF cost-parameter validation bounds (the pbkdf2 rounds bounds; the other knobs
 * are exercised implicitly by decrypting crafted headers in the smash test). */
static void test_kdf_validate(void) {
    dorado_kdf_params ok = dorado_kdf_pbkdf2(600000);
    check(dorado_kdf_validate(&ok) == NULL, "kdf validate: sane pbkdf2 rounds accepted");
    /* Zero rounds would "derive" an all-zero key without error. */
    dorado_kdf_params zero = dorado_kdf_pbkdf2(0);
    check(dorado_kdf_validate(&zero) == dorado_err_params, "kdf validate: pbkdf2 rounds 0 -> dorado_err_params");
    dorado_kdf_params huge = dorado_kdf_pbkdf2(0xffffffffu);
    check(dorado_kdf_validate(&huge) == dorado_err_params,
          "kdf validate: pbkdf2 rounds too large -> dorado_err_params");
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz);
    *len = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    return buf;
}

static void crosscompat_one(const char *file, const char *expect) {
    char path[256];
    snprintf(path, sizeof path, "tests/fixtures/%s", file);
    size_t dl = 0;
    uint8_t *data = read_file(path, &dl);
    if (!data) {
        check(0, file);
        return;
    }
    uint8_t *out = NULL;
    size_t ol = 0;
    const char *e = dorado_decrypt_password((const uint8_t *)"pw-cross", 8, NULL, 0, data, dl, &out, &ol);
    check(!e && ol == strlen(expect) && memcmp(out, expect, ol) == 0, file);
    free(out);
    free(data);
}

static void test_crosscompat(void) {
    crosscompat_one("argon_skein_256.mahi", "rust argon+skein+256");
    crosscompat_one("scrypt_hmac_512.mahi", "rust scrypt+hmac+512");
    crosscompat_one("pbkdf2_blake3_1024.mahi", "rust pbkdf2+blake3+1024");
    crosscompat_one("labeled.mahi", "rust labeled payload");

    /* multi-frame: 5000 'x' */
    size_t dl = 0;
    uint8_t *data = read_file("tests/fixtures/multichunk.mahi", &dl);
    uint8_t *out = NULL;
    size_t ol = 0;
    const char *e = data ? dorado_decrypt_password((const uint8_t *)"pw-cross", 8, NULL, 0, data, dl, &out, &ol) : "x";
    int ok = !e && ol == 5000;
    for (size_t i = 0; ok && i < ol; i++)
        if (out[i] != 'x') ok = 0;
    check(ok, "multichunk.mahi");
    free(out);
    free(data);
}

static void test_chunk_cap(void) {
    check(dorado_chunk_cap_from(NULL) == TEST_DEFAULT_MAX_CHUNK, "chunk cap: NULL -> default");
    check(dorado_chunk_cap_from("") == TEST_DEFAULT_MAX_CHUNK, "chunk cap: empty -> default");
    check(dorado_chunk_cap_from("abc") == TEST_DEFAULT_MAX_CHUNK, "chunk cap: unparseable -> default");
    check(dorado_chunk_cap_from("123abc") == TEST_DEFAULT_MAX_CHUNK, "chunk cap: trailing garbage -> default");
    check(dorado_chunk_cap_from("65536") == 65536u, "chunk cap: plain value passes through");
    check(dorado_chunk_cap_from("0") == 1u, "chunk cap: 0 -> clamped up to 1");
    check(dorado_chunk_cap_from("2147483648") == TEST_HARD_MAX_CHUNK, "chunk cap: > 1 GiB -> clamped to 1 GiB");
    check(dorado_chunk_cap_from("99999999999999999999") == TEST_DEFAULT_MAX_CHUNK,
          "chunk cap: overflow -> default");
}

/* xorshift64: a tiny deterministic PRNG so the smash test is reproducible (no
 * dependency on rand()/srand() and the same bytes across runs and platforms). */
static uint64_t smash_rng_state = 0x123456789abcdef0ULL;
static uint64_t smash_rand(void) {
    uint64_t x = smash_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    smash_rng_state = x;
    return x;
}

/* Deterministic randomized decrypt fuzzing. Feed thousands of pseudo-random,
 * truncated, and mutated-valid inputs to the decrypt entrypoint and assert it never
 * crashes. Run under SAN=1 this lets AddressSanitizer/UBSan catch any out-of-bounds
 * read or UB on the parse/framing path. A few inputs legitimately decrypt (e.g. an
 * untruncated copy of the valid container), so success is fine; the property under
 * test is "no crash, no leak", enforced by reaching the end and by the sanitizers. */
/* Under the sanitizers the smash loop dominates the whole suite (measured at
 * 99.8% of its runtime): the mutated-valid arm sometimes flips the header's
 * PBKDF2 rounds field into the millions (still under validate's 50M bound),
 * and each such iteration is a legitimate multi-second derivation. The PRNG
 * is deterministic, so the sanitized run's iterations are a strict prefix of
 * the plain run's; the sanitizers need path diversity, not raw count. */
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SMASH_ITERS 2000
#endif
#endif
#if !defined(SMASH_ITERS) && defined(__SANITIZE_ADDRESS__)
#define SMASH_ITERS 2000
#endif
#ifndef SMASH_ITERS
#define SMASH_ITERS 20000
#endif

static void test_smash(void) {
    const uint8_t *pw = (const uint8_t *)"pw-cross";
    size_t pwl = 8;

    /* A real container to seed the mutated-valid arm. */
    dorado_options o = opts(DORADO_T256, dorado_kdf_pbkdf2(4096), DORADO_MAC_SKEIN);
    uint8_t *valid = NULL;
    size_t valid_len = 0;
    if (dorado_encrypt_password(pw, pwl, &o, (const uint8_t *)"smash me", 8, &valid, &valid_len) != NULL) {
        check(0, "smash: seed container");
        return;
    }

    int ok = 1;
    uint8_t buf[512];
    for (int iter = 0; iter < SMASH_ITERS && ok; iter++) {
        size_t n;
        int arm = iter & 3;
        if (arm == 0) {
            /* fully random bytes, random length */
            n = (size_t)(smash_rand() % sizeof buf);
            for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)smash_rand();
        } else if (arm == 1) {
            /* random bytes that start with the real magic, to dive past it */
            n = (size_t)(smash_rand() % sizeof buf);
            if (n < 4) n = 4;
            memcpy(buf, "DRDO", 4);
            for (size_t i = 4; i < n; i++) buf[i] = (uint8_t)smash_rand();
        } else if (arm == 2) {
            /* a truncated prefix of the valid container */
            n = (size_t)(smash_rand() % (valid_len + 1));
            if (n > sizeof buf) n = sizeof buf;
            memcpy(buf, valid, n);
        } else {
            /* the valid container with a handful of bytes flipped */
            n = valid_len < sizeof buf ? valid_len : sizeof buf;
            memcpy(buf, valid, n);
            int flips = (int)(smash_rand() % 8) + 1;
            for (int f = 0; f < flips && n; f++) buf[smash_rand() % n] ^= (uint8_t)(1u << (smash_rand() & 7));
        }
        uint8_t *out = NULL;
        size_t ol = 0;
        const char *e = dorado_decrypt_password(pw, pwl, NULL, 0, buf, n, &out, &ol);
        /* On success the engine mallocs *out; free it. On error nothing is allocated.
         * Either outcome is acceptable; a memory bug would trip ASan/UBSan and abort
         * before we get here. */
        if (e == NULL) {
            free(out);
        }
    }
    check(ok, "smash: decrypt random/truncated/mutated inputs without crashing");
    free(valid);
}

int main(void) {
    test_threefish();
    test_hashes();
    test_engine();
    test_raw_authenticated_kat();
    test_raw_authenticated_matrix();
    test_raw_authenticated_security();
    test_derive_from_key_kat();
    test_derive_from_key_properties();
    test_kdf_validate();
    test_chunk_cap();
    test_smash();
    test_crosscompat();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

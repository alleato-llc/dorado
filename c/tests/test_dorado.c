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
    for (int iter = 0; iter < 20000 && ok; iter++) {
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
    check(ok, "smash: decrypt 20000 random/truncated/mutated inputs without crashing");
    free(valid);
}

int main(void) {
    test_threefish();
    test_hashes();
    test_engine();
    test_chunk_cap();
    test_smash();
    test_crosscompat();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

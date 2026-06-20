#include "dorado/engine.h"

#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "dorado/threefish.h"
#include "format.h"
#include "internal.h"
#include "kdf.h"
#include "mac.h"

dorado_kdf_params dorado_kdf_argon2id(uint32_t m_cost_kib, uint32_t t_cost, uint32_t p_cost) {
    dorado_kdf_params k = {0};
    k.kind = DORADO_KDF_ARGON2ID;
    k.m_cost = m_cost_kib;
    k.t_cost = t_cost;
    k.p_cost = p_cost;
    return k;
}

dorado_kdf_params dorado_kdf_scrypt(uint8_t log_n, uint32_t r, uint32_t p) {
    dorado_kdf_params k = {0};
    k.kind = DORADO_KDF_SCRYPT;
    k.log_n = log_n;
    k.r = r;
    k.p = p;
    return k;
}

dorado_kdf_params dorado_kdf_pbkdf2(uint32_t rounds) {
    dorado_kdf_params k = {0};
    k.kind = DORADO_KDF_PBKDF2;
    k.rounds = rounds;
    k.prf = 1;
    return k;
}

dorado_options dorado_default_options(void) {
    dorado_options o = {0};
    o.variant = DORADO_T256;
    o.kdf = dorado_kdf_argon2id(64 * 1024, 3, 1);
    o.mac = DORADO_MAC_SKEIN;
    o.chunk_size = DORADO_DEFAULT_CHUNK_BYTES;
    return o;
}

static size_t build_aad(uint8_t *buf, const uint8_t *header_bytes, size_t header_len, uint64_t index, int is_last,
                        const uint8_t *ct, size_t ct_len) {
    size_t n = 0;
    memcpy(buf + n, "DRDOchnk", 8);
    n += 8;
    if (index == 0) {
        memcpy(buf + n, header_bytes, header_len);
        n += header_len;
    }
    dorado_store64_be(buf + n, index);
    n += 8;
    buf[n++] = is_last ? 1 : 0;
    dorado_store32_be(buf + n, (uint32_t)ct_len);
    n += 4;
    memcpy(buf + n, ct, ct_len);
    n += ct_len;
    return n;
}

static const char *write_frame(FILE *out, int is_last, const uint8_t *ct, size_t ct_len, const uint8_t tag[32]) {
    uint8_t head[5];
    head[0] = (uint8_t)(is_last ? 1 : 0);
    dorado_store32_be(head + 1, (uint32_t)ct_len);
    if (fwrite(head, 1, 5, out) != 5) {
        return "write error";
    }
    if (ct_len && fwrite(ct, 1, ct_len, out) != ct_len) {
        return "write error";
    }
    if (fwrite(tag, 1, 32, out) != 32) {
        return "write error";
    }
    return NULL;
}

const char *dorado_encrypt_password_stream(const uint8_t *password, size_t password_len, const dorado_options *opts,
                                           FILE *in, FILE *out) {
    if (opts->label_len > DORADO_MAX_LABEL_LEN) {
        return "label too long";
    }
    int v = opts->variant;
    int bl = dorado_variant_len(v);
    if (bl == 0) {
        return "unknown variant";
    }
    if (opts->chunk_size == 0 || opts->chunk_size > DORADO_MAX_CHUNK_BYTES || opts->chunk_size % (uint32_t)bl != 0) {
        return "chunk size must be a positive multiple of the block size";
    }
    uint8_t salt[16];
    uint8_t iv[128];
    if (getentropy(salt, 16) != 0 || getentropy(iv, (size_t)bl) != 0) {
        return "RNG failure";
    }
    int kl = bl;
    uint8_t keymat[160];
    const char *e = dorado_kdf_derive(&opts->kdf, password, password_len, salt, 16, keymat, (size_t)kl + 32);
    if (e) {
        return e;
    }

    dorado_header h;
    memset(&h, 0, sizeof h);
    h.version = DORADO_VERSION;
    h.variant = v;
    h.kdf = opts->kdf;
    h.mac = opts->mac;
    h.chunk_size = opts->chunk_size;
    memcpy(h.salt, salt, 16);
    h.salt_len = 16;
    memcpy(h.tweak, opts->tweak, 16);
    memcpy(h.iv, iv, (size_t)bl);
    if (opts->label_len) {
        memcpy(h.label, opts->label, opts->label_len);
    }
    h.label_len = opts->label_len;
    uint8_t hb[DORADO_HEADER_MAX_BYTES];
    size_t hb_len = dorado_format_marshal(&h, hb);

    dorado_threefish tf;
    dorado_threefish_init(&tf, v, keymat, opts->tweak);
    dorado_ctr ctr;
    dorado_ctr_init(&ctr, &tf, iv);

    if (fwrite(hb, 1, hb_len, out) != hb_len) {
        return "write error";
    }

    size_t cs = opts->chunk_size;
    uint8_t *cur = malloc(cs);
    uint8_t *nxt = malloc(cs);
    uint8_t *aad = malloc(8 + hb_len + 13 + cs);
    if (!cur || !nxt || !aad) {
        free(cur);
        free(nxt);
        free(aad);
        return "out of memory";
    }
    size_t cur_len = fread(cur, 1, cs, in);
    uint64_t index = 0;
    const char *err = NULL;
    for (;;) {
        size_t nxt_len = fread(nxt, 1, cs, in);
        int is_last = nxt_len == 0;
        dorado_ctr_apply(&ctr, cur, cur_len);
        uint8_t tag[32];
        size_t aad_len = build_aad(aad, hb, hb_len, index, is_last, cur, cur_len);
        dorado_mac_tag(opts->mac, keymat + kl, aad, aad_len, tag);
        err = write_frame(out, is_last, cur, cur_len, tag);
        if (err || is_last) {
            break;
        }
        index++;
        uint8_t *tmp = cur;
        cur = nxt;
        nxt = tmp;
        cur_len = nxt_len;
    }
    free(cur);
    free(nxt);
    free(aad);
    return err;
}

const char *dorado_decrypt_password_stream(const uint8_t *password, size_t password_len, const uint8_t *expected_label,
                                           size_t expected_label_len, FILE *in, FILE *out) {
    dorado_header h;
    const char *e = dorado_format_read(in, &h);
    if (e) {
        return e;
    }
    if (expected_label) {
        if (expected_label_len != h.label_len || memcmp(expected_label, h.label, expected_label_len) != 0) {
            return "container label does not match the expected label";
        }
    }
    int bl = dorado_variant_len(h.variant);
    if (h.chunk_size == 0 || h.chunk_size > DORADO_MAX_CHUNK_BYTES || h.chunk_size % (uint32_t)bl != 0) {
        return "invalid chunk size in header";
    }
    e = dorado_kdf_validate(&h.kdf);
    if (e) {
        return e;
    }
    int kl = bl;
    uint8_t keymat[160];
    e = dorado_kdf_derive(&h.kdf, password, password_len, h.salt, h.salt_len, keymat, (size_t)kl + 32);
    if (e) {
        return e;
    }
    uint8_t hb[DORADO_HEADER_MAX_BYTES];
    size_t hb_len = dorado_format_marshal(&h, hb);

    dorado_threefish tf;
    dorado_threefish_init(&tf, h.variant, keymat, h.tweak);
    dorado_ctr ctr;
    dorado_ctr_init(&ctr, &tf, h.iv);

    size_t cs = h.chunk_size;
    uint8_t *ct = malloc(cs);
    uint8_t *aad = malloc(8 + hb_len + 13 + cs);
    if (!ct || !aad) {
        free(ct);
        free(aad);
        return "out of memory";
    }
    uint64_t index = 0;
    const char *err = NULL;
    for (;;) {
        uint8_t head[5];
        size_t got = fread(head, 1, 5, in);
        if (got == 0) {
            err = "stream ended before the final chunk (truncated)";
            break;
        }
        if (got < 5) {
            err = "incomplete frame header (truncated)";
            break;
        }
        int flag = head[0];
        if (flag > 1) {
            err = "invalid frame flag";
            break;
        }
        int is_last = flag == 1;
        uint32_t ct_len = dorado_load32_be(head + 1);
        if (ct_len > cs) {
            err = "frame length exceeds the header chunk size";
            break;
        }
        if (!dorado_read_full(in, ct, ct_len)) {
            err = "truncated frame ciphertext";
            break;
        }
        uint8_t tag[32];
        if (!dorado_read_full(in, tag, 32)) {
            err = "truncated frame tag";
            break;
        }
        size_t aad_len = build_aad(aad, hb, hb_len, index, is_last, ct, ct_len);
        if (!dorado_mac_verify(h.mac, keymat + kl, aad, aad_len, tag)) {
            err = "authentication failed (wrong password, corruption, or tampering)";
            break;
        }
        dorado_ctr_apply(&ctr, ct, ct_len);
        if (ct_len && fwrite(ct, 1, ct_len, out) != ct_len) {
            err = "write error";
            break;
        }
        if (is_last) {
            break;
        }
        if (ct_len != cs) {
            err = "non-final chunk is not full size";
            break;
        }
        index++;
    }
    free(ct);
    free(aad);
    return err;
}

const char *dorado_raw_ctr_stream(int variant, const uint8_t *key, const uint8_t *tweak, const uint8_t *iv, FILE *in,
                                  FILE *out) {
    int bl = dorado_variant_len(variant);
    if (bl == 0) {
        return "unknown variant";
    }
    dorado_threefish tf;
    dorado_threefish_init(&tf, variant, key, tweak);
    dorado_ctr ctr;
    dorado_ctr_init(&ctr, &tf, iv);
    size_t bufsz = (size_t)(65536 / bl) * (size_t)bl;
    uint8_t *buf = malloc(bufsz);
    if (!buf) {
        return "out of memory";
    }
    const char *err = NULL;
    for (;;) {
        size_t n = fread(buf, 1, bufsz, in);
        if (n == 0) {
            break;
        }
        dorado_ctr_apply(&ctr, buf, n);
        if (fwrite(buf, 1, n, out) != n) {
            err = "write error";
            break;
        }
        if (n < bufsz) {
            break;
        }
    }
    free(buf);
    return err;
}

const char *dorado_inspect_stream(FILE *in, dorado_container_info *info) {
    dorado_header h;
    const char *e = dorado_format_read(in, &h);
    if (e) {
        return e;
    }
    info->version = h.version;
    info->variant = h.variant;
    info->mac = h.mac;
    info->kdf = h.kdf;
    info->chunk_size = h.chunk_size;
    info->salt_len = h.salt_len;
    memcpy(info->tweak, h.tweak, 16);
    memcpy(info->label, h.label, h.label_len);
    info->label_len = h.label_len;
    return NULL;
}

/* ---- in-memory wrappers (fmemopen / open_memstream) ---- */

const char *dorado_encrypt_password(const uint8_t *password, size_t password_len, const dorado_options *opts,
                                    const uint8_t *plaintext, size_t plaintext_len, uint8_t **out, size_t *out_len) {
    /* fmemopen with size 0 is unsupported on some platforms (macOS), so use an
     * empty tmpfile for empty input. */
    FILE *in = plaintext_len ? fmemopen((void *)plaintext, plaintext_len, "rb") : tmpfile();
    if (!in) {
        return "input stream failed";
    }
    char *buf = NULL;
    size_t sz = 0;
    FILE *of = open_memstream(&buf, &sz);
    if (!of) {
        fclose(in);
        return "open_memstream failed";
    }
    const char *err = dorado_encrypt_password_stream(password, password_len, opts, in, of);
    fclose(in);
    fclose(of);
    if (err) {
        free(buf);
        return err;
    }
    *out = (uint8_t *)buf;
    *out_len = sz;
    return NULL;
}

const char *dorado_decrypt_password(const uint8_t *password, size_t password_len, const uint8_t *expected_label,
                                    size_t expected_label_len, const uint8_t *data, size_t data_len, uint8_t **out,
                                    size_t *out_len) {
    FILE *in = fmemopen((void *)data, data_len, "rb");
    if (!in) {
        return "fmemopen failed";
    }
    char *buf = NULL;
    size_t sz = 0;
    FILE *of = open_memstream(&buf, &sz);
    if (!of) {
        fclose(in);
        return "open_memstream failed";
    }
    const char *err =
        dorado_decrypt_password_stream(password, password_len, expected_label, expected_label_len, in, of);
    fclose(in);
    fclose(of);
    if (err) {
        free(buf);
        return err;
    }
    *out = (uint8_t *)buf;
    *out_len = sz;
    return NULL;
}

const char *dorado_inspect(const uint8_t *data, size_t data_len, dorado_container_info *info) {
    FILE *in = fmemopen((void *)data, data_len, "rb");
    if (!in) {
        return "fmemopen failed";
    }
    const char *e = dorado_inspect_stream(in, info);
    fclose(in);
    return e;
}

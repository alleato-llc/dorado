#include "format.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dorado/threefish.h"
#include "internal.h"

int dorado_read_full(FILE *in, uint8_t *buf, size_t n) {
    return fread(buf, 1, n, in) == n;
}

uint32_t dorado_chunk_cap_from(const char *s) {
    if (!s || s[0] == '\0') {
        return DORADO_DEFAULT_MAX_CHUNK_BYTES;
    }
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    /* Reject overflow and any trailing garbage (including leading-only sign/space,
     * which strtoul would skip; end == s means nothing parsed). */
    if (errno != 0 || end == s || *end != '\0') {
        return DORADO_DEFAULT_MAX_CHUNK_BYTES;
    }
    if (v < 1) {
        v = 1; /* clamp "0" up to the minimum */
    }
    if (v > DORADO_MAX_CHUNK_BYTES) {
        v = DORADO_MAX_CHUNK_BYTES; /* never exceed the hard ceiling */
    }
    return (uint32_t)v;
}

uint32_t dorado_effective_max_chunk_bytes(void) {
    return dorado_chunk_cap_from(getenv("DORADO_MAX_CHUNK_BYTES"));
}

size_t dorado_format_marshal(const dorado_header *h, uint8_t *out) {
    size_t n = 0;
    memcpy(out + n, DORADO_MAGIC, 4);
    n += 4;
    out[n++] = (uint8_t)h->version;
    out[n++] = (uint8_t)h->variant;
    switch (h->kdf.kind) {
        case DORADO_KDF_ARGON2ID:
            out[n++] = 1;
            dorado_store32_be(out + n, h->kdf.m_cost);
            n += 4;
            dorado_store32_be(out + n, h->kdf.t_cost);
            n += 4;
            dorado_store32_be(out + n, h->kdf.p_cost);
            n += 4;
            break;
        case DORADO_KDF_SCRYPT:
            out[n++] = 2;
            out[n++] = h->kdf.log_n;
            dorado_store32_be(out + n, h->kdf.r);
            n += 4;
            dorado_store32_be(out + n, h->kdf.p);
            n += 4;
            break;
        case DORADO_KDF_PBKDF2:
            out[n++] = 3;
            dorado_store32_be(out + n, h->kdf.rounds);
            n += 4;
            out[n++] = h->kdf.prf;
            break;
    }
    out[n++] = (uint8_t)h->mac;
    dorado_store32_be(out + n, h->chunk_size);
    n += 4;
    out[n++] = (uint8_t)h->salt_len;
    memcpy(out + n, h->salt, h->salt_len);
    n += h->salt_len;
    memcpy(out + n, h->tweak, 16);
    n += 16;
    size_t iv_len = (size_t)dorado_variant_len(h->variant);
    memcpy(out + n, h->iv, iv_len);
    n += iv_len;
    if (h->version >= 4) {
        out[n++] = (uint8_t)(h->label_len >> 8);
        out[n++] = (uint8_t)(h->label_len & 0xff);
        memcpy(out + n, h->label, h->label_len);
        n += h->label_len;
    }
    return n;
}

static int read_u32(FILE *in, uint32_t *x) {
    uint8_t b[4];
    if (!dorado_read_full(in, b, 4)) {
        return 0;
    }
    *x = dorado_load32_be(b);
    return 1;
}

#define RD(call, what) \
    do {               \
        if (!(call)) { \
            return "header truncated reading " what; \
        }              \
    } while (0)

const char *dorado_format_read(FILE *in, dorado_header *h) {
    uint8_t magic[4];
    RD(dorado_read_full(in, magic, 4), "magic");
    if (memcmp(magic, DORADO_MAGIC, 4) != 0) {
        return "not a dorado password file (bad magic)";
    }
    uint8_t v;
    RD(dorado_read_full(in, &v, 1), "version");
    if (v != 3 && v != DORADO_VERSION) {
        return "unsupported format version";
    }
    h->version = v;
    uint8_t var;
    RD(dorado_read_full(in, &var, 1), "variant");
    if (var > 2) {
        return "unknown variant code";
    }
    h->variant = var;

    uint8_t kid;
    RD(dorado_read_full(in, &kid, 1), "kdf id");
    memset(&h->kdf, 0, sizeof h->kdf);
    if (kid == DORADO_KDF_ARGON2ID) {
        h->kdf.kind = DORADO_KDF_ARGON2ID;
        RD(read_u32(in, &h->kdf.m_cost), "m_cost");
        RD(read_u32(in, &h->kdf.t_cost), "t_cost");
        RD(read_u32(in, &h->kdf.p_cost), "p_cost");
    } else if (kid == DORADO_KDF_SCRYPT) {
        h->kdf.kind = DORADO_KDF_SCRYPT;
        RD(dorado_read_full(in, &h->kdf.log_n, 1), "log_n");
        RD(read_u32(in, &h->kdf.r), "r");
        RD(read_u32(in, &h->kdf.p), "p");
    } else if (kid == DORADO_KDF_PBKDF2) {
        h->kdf.kind = DORADO_KDF_PBKDF2;
        RD(read_u32(in, &h->kdf.rounds), "rounds");
        uint8_t prf;
        RD(dorado_read_full(in, &prf, 1), "prf");
        if (prf != 1) {
            return "unknown prf id";
        }
        h->kdf.prf = prf;
    } else {
        return "unknown kdf id";
    }

    uint8_t mac;
    RD(dorado_read_full(in, &mac, 1), "mac id");
    if (mac < 1 || mac > 3) {
        return "unknown mac id";
    }
    h->mac = mac;
    RD(read_u32(in, &h->chunk_size), "chunk size");
    uint8_t salt_len;
    RD(dorado_read_full(in, &salt_len, 1), "salt len");
    h->salt_len = salt_len;
    RD(dorado_read_full(in, h->salt, salt_len), "salt");
    RD(dorado_read_full(in, h->tweak, 16), "tweak");
    RD(dorado_read_full(in, h->iv, (size_t)dorado_variant_len(h->variant)), "iv");
    if (v >= 4) {
        uint8_t ll[2];
        RD(dorado_read_full(in, ll, 2), "label len");
        size_t label_len = dorado_load16_be(ll);
        if (label_len > DORADO_MAX_LABEL_LEN) {
            return "label too long";
        }
        RD(dorado_read_full(in, h->label, label_len), "label");
        h->label_len = label_len;
    } else {
        h->label_len = 0;
    }
    return NULL;
}

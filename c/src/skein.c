#include "dorado/skein.h"

#include <string.h>

#include "dorado/threefish.h"
#include "internal.h"

#define BLOCK 64

/* UBI block type values (the 6-bit type field of the tweak). */
#define T_KEY 0u
#define T_CFG 4u
#define T_MSG 48u
#define T_OUT 63u

static void build_tweak(uint8_t tw[16], uint64_t position, uint64_t ty, int first, int last) {
    uint64_t t1 = ty << 56;
    if (first) {
        t1 |= UINT64_C(1) << 62;
    }
    if (last) {
        t1 |= UINT64_C(1) << 63;
    }
    dorado_store64_le(tw, position);
    dorado_store64_le(tw + 8, t1);
}

/* One full UBI pass, chaining msg into the chaining value g (bounded; for the
 * config and key passes). */
static void ubi(uint8_t g[64], const uint8_t *msg, size_t total, uint64_t ty) {
    size_t offset = 0;
    uint64_t position = 0;
    int first = 1;
    for (;;) {
        size_t take = total - offset < BLOCK ? total - offset : BLOCK;
        uint8_t block[BLOCK];
        memset(block, 0, BLOCK);
        memcpy(block, msg + offset, take);
        position += take;
        offset += take;
        int last = offset >= total;
        uint8_t tw[16];
        build_tweak(tw, position, ty, first, last);
        dorado_threefish tf;
        dorado_threefish_init(&tf, DORADO_T512, g, tw);
        uint8_t enc[BLOCK];
        dorado_threefish_encrypt_block(&tf, enc, block);
        for (int i = 0; i < BLOCK; i++) {
            g[i] = enc[i] ^ block[i];
        }
        first = 0;
        if (last) {
            break;
        }
    }
}

static void config_block(uint8_t c[32], uint64_t out_bits) {
    memset(c, 0, 32);
    c[0] = 'S';
    c[1] = 'H';
    c[2] = 'A';
    c[3] = '3';
    c[4] = 1; /* version 1 (16-bit little-endian) */
    dorado_store64_le(c + 8, out_bits);
}

static void output_into(const uint8_t g[64], uint8_t *out, size_t out_len) {
    uint64_t counter = 0;
    size_t written = 0;
    while (written < out_len) {
        uint8_t block[64];
        memcpy(block, g, 64);
        uint8_t ctr[8];
        dorado_store64_le(ctr, counter);
        ubi(block, ctr, 8, T_OUT);
        size_t n = out_len - written < BLOCK ? out_len - written : BLOCK;
        memcpy(out + written, block, n);
        written += n;
        counter++;
    }
}

void dorado_skein512_init(dorado_skein512 *s, size_t out_len) {
    memset(s->g, 0, 64);
    uint8_t cfg[32];
    config_block(cfg, (uint64_t)out_len * 8);
    ubi(s->g, cfg, 32, T_CFG);
    memset(s->buffer, 0, 64);
    s->buffer_len = 0;
    s->position = 0;
    s->first = 1;
    s->out_len = out_len;
}

void dorado_skein512_init_mac(dorado_skein512 *s, const uint8_t *key, size_t key_len, size_t out_len) {
    memset(s->g, 0, 64);
    if (key_len > 0) {
        ubi(s->g, key, key_len, T_KEY);
    }
    uint8_t cfg[32];
    config_block(cfg, (uint64_t)out_len * 8);
    ubi(s->g, cfg, 32, T_CFG);
    memset(s->buffer, 0, 64);
    s->buffer_len = 0;
    s->position = 0;
    s->first = 1;
    s->out_len = out_len;
}

static void commit(dorado_skein512 *s, const uint8_t block[64], size_t nbytes, int last) {
    s->position += nbytes;
    uint8_t tw[16];
    build_tweak(tw, s->position, T_MSG, s->first, last);
    dorado_threefish tf;
    dorado_threefish_init(&tf, DORADO_T512, s->g, tw);
    uint8_t enc[64];
    dorado_threefish_encrypt_block(&tf, enc, block);
    for (int i = 0; i < 64; i++) {
        s->g[i] = enc[i] ^ block[i];
    }
    s->first = 0;
}

void dorado_skein512_update(dorado_skein512 *s, const uint8_t *data, size_t len) {
    if (len == 0) {
        return;
    }
    if (s->buffer_len > 0) {
        size_t take = BLOCK - s->buffer_len < len ? BLOCK - s->buffer_len : len;
        memcpy(s->buffer + s->buffer_len, data, take);
        s->buffer_len += take;
        data += take;
        len -= take;
        if (s->buffer_len == BLOCK && len > 0) {
            commit(s, s->buffer, BLOCK, 0);
            s->buffer_len = 0;
        }
    }
    while (len > BLOCK) {
        commit(s, data, BLOCK, 0);
        data += BLOCK;
        len -= BLOCK;
    }
    if (len > 0) {
        memcpy(s->buffer, data, len);
        s->buffer_len = len;
    }
}

void dorado_skein512_finalize(const dorado_skein512 *s, uint8_t *out) {
    dorado_skein512 tmp = *s;
    uint8_t block[64];
    memset(block, 0, 64);
    memcpy(block, tmp.buffer, tmp.buffer_len);
    commit(&tmp, block, tmp.buffer_len, 1);
    output_into(tmp.g, out, s->out_len);
}

void dorado_skein512_hash(size_t out_len, const uint8_t *msg, size_t msg_len, uint8_t *out) {
    dorado_skein512 s;
    dorado_skein512_init(&s, out_len);
    dorado_skein512_update(&s, msg, msg_len);
    dorado_skein512_finalize(&s, out);
}

void dorado_skein512_mac(const uint8_t *key, size_t key_len, size_t out_len, const uint8_t *msg, size_t msg_len,
                         uint8_t *out) {
    dorado_skein512 s;
    dorado_skein512_init_mac(&s, key, key_len, out_len);
    dorado_skein512_update(&s, msg, msg_len);
    dorado_skein512_finalize(&s, out);
}

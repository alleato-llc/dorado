#include "dorado/blake3.h"

#include <string.h>

#include "internal.h"

#define BLOCK_BYTES 64
#define CHUNK_BYTES 1024

#define CHUNK_START (1u << 0)
#define CHUNK_END (1u << 1)
#define FLAG_PARENT (1u << 2)
#define FLAG_ROOT (1u << 3)
#define KEYED_HASH (1u << 4)

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static const uint8_t MSG_PERMUTATION[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

static void g(uint32_t *s, int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = dorado_rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = dorado_rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = dorado_rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = dorado_rotr32(s[b] ^ s[c], 7);
}

static void compress(uint32_t out[16], const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
                     uint32_t b_len, uint32_t flags) {
    uint32_t state[16] = {
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        (uint32_t)counter, (uint32_t)(counter >> 32), b_len, flags,
    };
    uint32_t m[16];
    memcpy(m, block, sizeof m);
    for (int round = 0; round < 7; round++) {
        g(state, 0, 4, 8, 12, m[0], m[1]);
        g(state, 1, 5, 9, 13, m[2], m[3]);
        g(state, 2, 6, 10, 14, m[4], m[5]);
        g(state, 3, 7, 11, 15, m[6], m[7]);
        g(state, 0, 5, 10, 15, m[8], m[9]);
        g(state, 1, 6, 11, 12, m[10], m[11]);
        g(state, 2, 7, 8, 13, m[12], m[13]);
        g(state, 3, 4, 9, 14, m[14], m[15]);
        if (round < 6) {
            uint32_t permuted[16];
            for (int i = 0; i < 16; i++) {
                permuted[i] = m[MSG_PERMUTATION[i]];
            }
            memcpy(m, permuted, sizeof m);
        }
    }
    for (int i = 0; i < 8; i++) {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    memcpy(out, state, sizeof state);
}

static void words_from_block(uint32_t out[16], const uint8_t *b, size_t len) {
    uint8_t padded[BLOCK_BYTES];
    memset(padded, 0, BLOCK_BYTES);
    memcpy(padded, b, len);
    for (int i = 0; i < 16; i++) {
        out[i] = dorado_load32_le(padded + i * 4);
    }
}

typedef struct {
    uint32_t input_cv[8];
    uint32_t block[16];
    uint64_t counter;
    uint32_t b_len;
    uint32_t flags;
} b3_output;

static void output_chaining_value(const b3_output *o, uint32_t cv[8]) {
    uint32_t full[16];
    compress(full, o->input_cv, o->block, o->counter, o->b_len, o->flags);
    memcpy(cv, full, 8 * sizeof(uint32_t));
}

static void output_root(const b3_output *o, uint8_t *out, size_t out_len) {
    uint64_t counter = 0;
    size_t written = 0;
    while (written < out_len) {
        uint32_t words[16];
        compress(words, o->input_cv, o->block, counter, o->b_len, o->flags | FLAG_ROOT);
        for (int i = 0; i < 16 && written < out_len; i++) {
            uint8_t w[4];
            dorado_store32_le(w, words[i]);
            size_t n = out_len - written < 4 ? out_len - written : 4;
            memcpy(out + written, w, n);
            written += n;
        }
        counter++;
    }
}

static uint32_t chunk_start_flag(const dorado_blake3_chunk *cs) {
    return cs->blocks_compressed == 0 ? CHUNK_START : 0;
}

static size_t chunk_len(const dorado_blake3_chunk *cs) {
    return BLOCK_BYTES * cs->blocks_compressed + cs->block_len;
}

static void chunk_init(dorado_blake3_chunk *cs, const uint32_t key[8], uint64_t counter, uint32_t flags) {
    memcpy(cs->cv, key, 8 * sizeof(uint32_t));
    cs->chunk_counter = counter;
    memset(cs->block, 0, BLOCK_BYTES);
    cs->block_len = 0;
    cs->blocks_compressed = 0;
    cs->flags = flags;
}

static void chunk_update(dorado_blake3_chunk *cs, const uint8_t *data, size_t len) {
    while (len > 0) {
        if (cs->block_len == BLOCK_BYTES) {
            uint32_t bw[16];
            words_from_block(bw, cs->block, BLOCK_BYTES);
            uint32_t out[16];
            compress(out, cs->cv, bw, cs->chunk_counter, BLOCK_BYTES, cs->flags | chunk_start_flag(cs));
            memcpy(cs->cv, out, 8 * sizeof(uint32_t));
            cs->blocks_compressed++;
            memset(cs->block, 0, BLOCK_BYTES);
            cs->block_len = 0;
        }
        size_t take = BLOCK_BYTES - cs->block_len < len ? BLOCK_BYTES - cs->block_len : len;
        memcpy(cs->block + cs->block_len, data, take);
        cs->block_len += take;
        data += take;
        len -= take;
    }
}

static void chunk_output(const dorado_blake3_chunk *cs, b3_output *o) {
    memcpy(o->input_cv, cs->cv, 8 * sizeof(uint32_t));
    words_from_block(o->block, cs->block, cs->block_len);
    o->counter = cs->chunk_counter;
    o->b_len = (uint32_t)cs->block_len;
    o->flags = cs->flags | chunk_start_flag(cs) | CHUNK_END;
}

static void parent_output(b3_output *o, const uint32_t left[8], const uint32_t right[8], const uint32_t key[8],
                          uint32_t flags) {
    memcpy(o->input_cv, key, 8 * sizeof(uint32_t));
    memcpy(o->block, left, 8 * sizeof(uint32_t));
    memcpy(o->block + 8, right, 8 * sizeof(uint32_t));
    o->counter = 0;
    o->b_len = BLOCK_BYTES;
    o->flags = flags | FLAG_PARENT;
}

static void parent_cv(uint32_t cv[8], const uint32_t left[8], const uint32_t right[8], const uint32_t key[8],
                      uint32_t flags) {
    b3_output o;
    parent_output(&o, left, right, key, flags);
    output_chaining_value(&o, cv);
}

void dorado_blake3_init(dorado_blake3 *h) {
    memcpy(h->key, IV, sizeof h->key);
    h->flags = 0;
    chunk_init(&h->chunk, h->key, 0, 0);
    h->cv_stack_len = 0;
}

void dorado_blake3_init_keyed(dorado_blake3 *h, const uint8_t key32[32]) {
    for (int i = 0; i < 8; i++) {
        h->key[i] = dorado_load32_le(key32 + i * 4);
    }
    h->flags = KEYED_HASH;
    chunk_init(&h->chunk, h->key, 0, h->flags);
    h->cv_stack_len = 0;
}

static void add_chunk_cv(dorado_blake3 *h, uint32_t new_cv[8], uint64_t total_chunks) {
    while ((total_chunks & 1) == 0) {
        uint32_t merged[8];
        parent_cv(merged, h->cv_stack[--h->cv_stack_len], new_cv, h->key, h->flags);
        memcpy(new_cv, merged, 8 * sizeof(uint32_t));
        total_chunks >>= 1;
    }
    memcpy(h->cv_stack[h->cv_stack_len++], new_cv, 8 * sizeof(uint32_t));
}

void dorado_blake3_update(dorado_blake3 *h, const uint8_t *data, size_t len) {
    while (len > 0) {
        if (chunk_len(&h->chunk) == CHUNK_BYTES) {
            b3_output o;
            chunk_output(&h->chunk, &o);
            uint32_t chunk_cv[8];
            output_chaining_value(&o, chunk_cv);
            uint64_t total = h->chunk.chunk_counter + 1;
            add_chunk_cv(h, chunk_cv, total);
            chunk_init(&h->chunk, h->key, total, h->flags);
        }
        size_t want = CHUNK_BYTES - chunk_len(&h->chunk);
        size_t take = want < len ? want : len;
        chunk_update(&h->chunk, data, take);
        data += take;
        len -= take;
    }
}

void dorado_blake3_finalize(const dorado_blake3 *h, uint8_t *out, size_t out_len) {
    b3_output o;
    chunk_output(&h->chunk, &o);
    for (int i = h->cv_stack_len - 1; i >= 0; i--) {
        uint32_t cv[8];
        output_chaining_value(&o, cv);
        parent_output(&o, h->cv_stack[i], cv, h->key, h->flags);
    }
    output_root(&o, out, out_len);
}

void dorado_blake3_hash(size_t out_len, const uint8_t *data, size_t len, uint8_t *out) {
    dorado_blake3 h;
    dorado_blake3_init(&h);
    dorado_blake3_update(&h, data, len);
    dorado_blake3_finalize(&h, out, out_len);
}

void dorado_blake3_keyed_mac(const uint8_t key32[32], size_t out_len, const uint8_t *data, size_t len, uint8_t *out) {
    dorado_blake3 h;
    dorado_blake3_init_keyed(&h, key32);
    dorado_blake3_update(&h, data, len);
    dorado_blake3_finalize(&h, out, out_len);
}

#include "dorado/threefish.h"

#include <string.h>

#include "internal.h"

/* Skein 1.3 key-schedule constant (the round-3 NIST value). Do not change. */
#define C240 UINT64_C(0x1BD11BDAA9FC1A22)

/* Per-variant rotation and permutation tables (Skein 1.3). Verified against
 * official test vectors and must not be changed. */
static const uint32_t ROT256[2][8] = {
    {14, 52, 23, 5, 25, 46, 58, 32},
    {16, 57, 40, 37, 33, 12, 22, 32},
};
static const uint8_t PERM256[4] = {0, 3, 2, 1};

static const uint32_t ROT512[4][8] = {
    {46, 33, 17, 44, 39, 13, 25, 8},
    {36, 27, 49, 9, 30, 50, 29, 35},
    {19, 14, 36, 54, 34, 10, 39, 56},
    {37, 42, 39, 56, 24, 17, 43, 22},
};
static const uint8_t PERM512[8] = {2, 1, 4, 7, 6, 5, 0, 3};

static const uint32_t ROT1024[8][8] = {
    {24, 38, 33, 5, 41, 16, 31, 9},
    {13, 19, 4, 20, 9, 34, 44, 48},
    {8, 10, 51, 48, 37, 56, 47, 35},
    {47, 55, 13, 41, 31, 51, 46, 52},
    {8, 49, 34, 47, 12, 4, 19, 23},
    {17, 18, 41, 28, 47, 53, 42, 31},
    {22, 23, 59, 16, 44, 42, 44, 37},
    {37, 52, 17, 25, 30, 41, 25, 20},
};
static const uint8_t PERM1024[16] = {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};

int dorado_variant_len(int variant) {
    switch (variant) {
        case DORADO_T256:
            return 32;
        case DORADO_T512:
            return 64;
        case DORADO_T1024:
            return 128;
        default:
            return 0;
    }
}

int dorado_threefish_init(dorado_threefish *tf, int variant, const uint8_t *key, const uint8_t *tweak) {
    switch (variant) {
        case DORADO_T256:
            tf->nw = 4;
            tf->rounds = 72;
            tf->rot = ROT256;
            tf->perm = PERM256;
            break;
        case DORADO_T512:
            tf->nw = 8;
            tf->rounds = 72;
            tf->rot = ROT512;
            tf->perm = PERM512;
            break;
        case DORADO_T1024:
            tf->nw = 16;
            tf->rounds = 80;
            tf->rot = ROT1024;
            tf->perm = PERM1024;
            break;
        default:
            return -1;
    }
    tf->block_bytes = tf->nw * 8;
    uint64_t parity = C240;
    for (int i = 0; i < tf->nw; i++) {
        uint64_t w = dorado_load64_le(key + i * 8);
        tf->ek[i] = w;
        parity ^= w;
    }
    tf->ek[tf->nw] = parity;
    uint64_t t0 = dorado_load64_le(tweak);
    uint64_t t1 = dorado_load64_le(tweak + 8);
    tf->et[0] = t0;
    tf->et[1] = t1;
    tf->et[2] = t0 ^ t1;
    return 0;
}

static void add_subkey(const dorado_threefish *tf, uint64_t *state, int s) {
    int nw = tf->nw;
    for (int i = 0; i < nw; i++) {
        uint64_t k = tf->ek[(s + i) % (nw + 1)];
        if (i == nw - 3) {
            k += tf->et[s % 3];
        } else if (i == nw - 2) {
            k += tf->et[(s + 1) % 3];
        } else if (i == nw - 1) {
            k += (uint64_t)s;
        }
        state[i] += k;
    }
}

static void sub_subkey(const dorado_threefish *tf, uint64_t *state, int s) {
    int nw = tf->nw;
    for (int i = 0; i < nw; i++) {
        uint64_t k = tf->ek[(s + i) % (nw + 1)];
        if (i == nw - 3) {
            k += tf->et[s % 3];
        } else if (i == nw - 2) {
            k += tf->et[(s + 1) % 3];
        } else if (i == nw - 1) {
            k += (uint64_t)s;
        }
        state[i] -= k;
    }
}

static void encrypt_state(const dorado_threefish *tf, uint64_t *state) {
    int nw = tf->nw;
    uint64_t scratch[16];
    for (int r = 0; r < tf->rounds; r++) {
        if (r % 4 == 0) {
            add_subkey(tf, state, r / 4);
        }
        for (int j = 0; j < nw / 2; j++) {
            uint64_t x0 = state[2 * j];
            uint64_t x1 = state[2 * j + 1];
            uint64_t y0 = x0 + x1;
            uint64_t y1 = dorado_rotl64(x1, tf->rot[j][r % 8]) ^ y0;
            state[2 * j] = y0;
            state[2 * j + 1] = y1;
        }
        for (int i = 0; i < nw; i++) {
            scratch[i] = state[tf->perm[i]];
        }
        memcpy(state, scratch, (size_t)nw * 8);
    }
    add_subkey(tf, state, tf->rounds / 4);
}

static void decrypt_state(const dorado_threefish *tf, uint64_t *state) {
    int nw = tf->nw;
    uint64_t scratch[16];
    sub_subkey(tf, state, tf->rounds / 4);
    for (int r = tf->rounds - 1; r >= 0; r--) {
        for (int i = 0; i < nw; i++) {
            scratch[tf->perm[i]] = state[i];
        }
        memcpy(state, scratch, (size_t)nw * 8);
        for (int j = 0; j < nw / 2; j++) {
            uint64_t y0 = state[2 * j];
            uint64_t y1 = state[2 * j + 1];
            uint64_t x1 = dorado_rotr64(y1 ^ y0, tf->rot[j][r % 8]);
            uint64_t x0 = y0 - x1;
            state[2 * j] = x0;
            state[2 * j + 1] = x1;
        }
        if (r % 4 == 0) {
            sub_subkey(tf, state, r / 4);
        }
    }
}

void dorado_threefish_encrypt_block(const dorado_threefish *tf, uint8_t *out, const uint8_t *in) {
    uint64_t state[16];
    for (int i = 0; i < tf->nw; i++) {
        state[i] = dorado_load64_le(in + i * 8);
    }
    encrypt_state(tf, state);
    for (int i = 0; i < tf->nw; i++) {
        dorado_store64_le(out + i * 8, state[i]);
    }
}

void dorado_threefish_decrypt_block(const dorado_threefish *tf, uint8_t *out, const uint8_t *in) {
    uint64_t state[16];
    for (int i = 0; i < tf->nw; i++) {
        state[i] = dorado_load64_le(in + i * 8);
    }
    decrypt_state(tf, state);
    for (int i = 0; i < tf->nw; i++) {
        dorado_store64_le(out + i * 8, state[i]);
    }
}

void dorado_ctr_init(dorado_ctr *ctr, const dorado_threefish *tf, const uint8_t *iv) {
    ctr->tf = tf;
    memcpy(ctr->counter, iv, (size_t)tf->block_bytes);
}

void dorado_ctr_apply(dorado_ctr *ctr, uint8_t *buf, size_t len) {
    int bs = ctr->tf->block_bytes;
    uint8_t ks[128];
    for (size_t off = 0; off < len; off += (size_t)bs) {
        dorado_threefish_encrypt_block(ctr->tf, ks, ctr->counter);
        size_t n = len - off < (size_t)bs ? len - off : (size_t)bs;
        for (size_t j = 0; j < n; j++) {
            buf[off + j] ^= ks[j];
        }
        /* increment the counter as a big-endian integer */
        for (int i = bs - 1; i >= 0; i--) {
            if (++ctr->counter[i] != 0) {
                break;
            }
        }
    }
}

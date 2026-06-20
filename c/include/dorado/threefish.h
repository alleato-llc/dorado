/* From-scratch Threefish (256/512/1024-bit), the tweakable block cipher at the core
 * of Skein (Skein 1.3, including the round-3 NIST C240 tweak), plus CTR mode. C port
 * of the dorado Rust crate; keys, tweaks, and blocks are little-endian. Educational
 * and unaudited. */
#ifndef DORADO_THREEFISH_H
#define DORADO_THREEFISH_H

#include <stddef.h>
#include <stdint.h>

/* Variant codes (also the on-disk header values). */
enum {
    DORADO_T256 = 0,
    DORADO_T512 = 1,
    DORADO_T1024 = 2,
};

/* An expanded Threefish key schedule. Stack-allocatable. */
typedef struct {
    uint64_t ek[17]; /* nw key words + parity word (nw <= 16) */
    uint64_t et[3];  /* t0, t1, t0 ^ t1 */
    const uint32_t (*rot)[8];
    const uint8_t *perm;
    int rounds;
    int nw;
    int block_bytes; /* nw * 8 */
} dorado_threefish;

/* Initialize tf for the given variant. key and tweak must be block_bytes and 16
 * bytes. Returns 0 on success, -1 on an unknown variant. */
int dorado_threefish_init(dorado_threefish *tf, int variant, const uint8_t *key, const uint8_t *tweak);

/* The variant's key/block/IV length in bytes (0 for an unknown variant). */
int dorado_variant_len(int variant);

void dorado_threefish_encrypt_block(const dorado_threefish *tf, uint8_t *out, const uint8_t *in);
void dorado_threefish_decrypt_block(const dorado_threefish *tf, uint8_t *out, const uint8_t *in);

/* A resumable CTR keystream: apply() may be called per chunk, the counter carrying
 * across calls, so a file streams in constant memory and stays identical to
 * whole-file CTR (non-final chunks are whole blocks). */
typedef struct {
    const dorado_threefish *tf;
    uint8_t counter[128];
} dorado_ctr;

void dorado_ctr_init(dorado_ctr *ctr, const dorado_threefish *tf, const uint8_t *iv);
void dorado_ctr_apply(dorado_ctr *ctr, uint8_t *buf, size_t len);

#endif /* DORADO_THREEFISH_H */

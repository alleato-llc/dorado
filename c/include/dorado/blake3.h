/* From-scratch BLAKE3 hash and keyed MAC, using the streaming chunk-stack
 * algorithm. The inherent finalize is an extendable-output function. */
#ifndef DORADO_BLAKE3_H
#define DORADO_BLAKE3_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t block[64];
    size_t block_len;
    uint64_t blocks_compressed;
    uint32_t flags;
} dorado_blake3_chunk;

typedef struct {
    uint32_t key[8];
    uint32_t flags;
    dorado_blake3_chunk chunk;
    uint32_t cv_stack[54][8]; /* max input 2^64 -> depth <= 54 */
    int cv_stack_len;
} dorado_blake3;

void dorado_blake3_init(dorado_blake3 *h);
void dorado_blake3_init_keyed(dorado_blake3 *h, const uint8_t key32[32]);
void dorado_blake3_update(dorado_blake3 *h, const uint8_t *data, size_t len);
void dorado_blake3_finalize(const dorado_blake3 *h, uint8_t *out, size_t out_len);

void dorado_blake3_hash(size_t out_len, const uint8_t *data, size_t len, uint8_t *out);
void dorado_blake3_keyed_mac(const uint8_t key32[32], size_t out_len, const uint8_t *data, size_t len, uint8_t *out);

#endif /* DORADO_BLAKE3_H */

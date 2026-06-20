/* From-scratch Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI.
 * Incremental (streams in constant memory) with one-shot helpers. */
#ifndef DORADO_SKEIN_H
#define DORADO_SKEIN_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t g[64];
    uint8_t buffer[64];
    size_t buffer_len;
    uint64_t position;
    int first;
    size_t out_len;
} dorado_skein512;

void dorado_skein512_init(dorado_skein512 *s, size_t out_len);
void dorado_skein512_init_mac(dorado_skein512 *s, const uint8_t *key, size_t key_len, size_t out_len);
void dorado_skein512_update(dorado_skein512 *s, const uint8_t *data, size_t len);
/* Writes out_len bytes into out. Does not change the hasher state. */
void dorado_skein512_finalize(const dorado_skein512 *s, uint8_t *out);

void dorado_skein512_hash(size_t out_len, const uint8_t *msg, size_t msg_len, uint8_t *out);
void dorado_skein512_mac(const uint8_t *key, size_t key_len, size_t out_len, const uint8_t *msg, size_t msg_len,
                         uint8_t *out);

#endif /* DORADO_SKEIN_H */

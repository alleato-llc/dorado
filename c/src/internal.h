/* Internal little-endian / big-endian byte helpers shared across the C port. */
#ifndef DORADO_INTERNAL_H
#define DORADO_INTERNAL_H

#include <stdint.h>

static inline uint64_t dorado_load64_le(const uint8_t *b) {
    return (uint64_t)b[0] | (uint64_t)b[1] << 8 | (uint64_t)b[2] << 16 | (uint64_t)b[3] << 24 |
           (uint64_t)b[4] << 32 | (uint64_t)b[5] << 40 | (uint64_t)b[6] << 48 | (uint64_t)b[7] << 56;
}

static inline void dorado_store64_le(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> (8 * i));
    }
}

static inline uint32_t dorado_load32_le(const uint8_t *b) {
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static inline void dorado_store32_le(uint8_t *b, uint32_t v) {
    for (int i = 0; i < 4; i++) {
        b[i] = (uint8_t)(v >> (8 * i));
    }
}

static inline uint16_t dorado_load16_be(const uint8_t *b) {
    return (uint16_t)((uint16_t)b[0] << 8 | (uint16_t)b[1]);
}

static inline uint32_t dorado_load32_be(const uint8_t *b) {
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | (uint32_t)b[3];
}

static inline void dorado_store32_be(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static inline void dorado_store64_be(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static inline uint64_t dorado_rotl64(uint64_t x, unsigned n) {
    return (x << n) | (x >> (64 - n));
}

static inline uint64_t dorado_rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint32_t dorado_rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

#endif /* DORADO_INTERNAL_H */

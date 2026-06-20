/* Internal: the MAC menu (Skein-512, keyed BLAKE3, HMAC-SHA256), all 32-byte tags. */
#ifndef DORADO_MAC_H
#define DORADO_MAC_H

#include <stddef.h>
#include <stdint.h>

void dorado_mac_tag(int mac, const uint8_t mac_key[32], const uint8_t *signed_data, size_t signed_len,
                    uint8_t out[32]);

/* Recompute the tag and compare it in constant time. Returns 1 if equal. */
int dorado_mac_verify(int mac, const uint8_t mac_key[32], const uint8_t *signed_data, size_t signed_len,
                      const uint8_t received[32]);

#endif /* DORADO_MAC_H */

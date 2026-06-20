#include "mac.h"

#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include "dorado/blake3.h"
#include "dorado/engine.h"
#include "dorado/skein.h"

void dorado_mac_tag(int mac, const uint8_t mac_key[32], const uint8_t *signed_data, size_t signed_len,
                    uint8_t out[32]) {
    switch (mac) {
        case DORADO_MAC_SKEIN:
            dorado_skein512_mac(mac_key, 32, 32, signed_data, signed_len, out);
            break;
        case DORADO_MAC_BLAKE3:
            dorado_blake3_keyed_mac(mac_key, 32, signed_data, signed_len, out);
            break;
        case DORADO_MAC_HMAC: {
            unsigned int len = 32;
            HMAC(EVP_sha256(), mac_key, 32, signed_data, signed_len, out, &len);
            break;
        }
        default:
            break;
    }
}

int dorado_mac_verify(int mac, const uint8_t mac_key[32], const uint8_t *signed_data, size_t signed_len,
                      const uint8_t received[32]) {
    uint8_t expected[32];
    dorado_mac_tag(mac, mac_key, signed_data, signed_len, expected);
    return CRYPTO_memcmp(expected, received, 32) == 0;
}

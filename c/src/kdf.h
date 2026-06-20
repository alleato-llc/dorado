/* Internal: key derivation (Argon2id via libargon2; scrypt and PBKDF2 via OpenSSL)
 * and validation of untrusted cost parameters. */
#ifndef DORADO_KDF_H
#define DORADO_KDF_H

#include "dorado/engine.h"

const char *dorado_kdf_derive(const dorado_kdf_params *p, const uint8_t *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len, uint8_t *out, size_t out_len);

const char *dorado_kdf_validate(const dorado_kdf_params *p);

#endif /* DORADO_KDF_H */

#include "kdf.h"

#include <argon2.h>
#include <openssl/evp.h>

const char *dorado_kdf_derive(const dorado_kdf_params *p, const uint8_t *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len, uint8_t *out, size_t out_len) {
    switch (p->kind) {
        case DORADO_KDF_ARGON2ID: {
            int rc = argon2id_hash_raw(p->t_cost, p->m_cost, p->p_cost, password, password_len, salt, salt_len, out,
                                       out_len);
            return rc == ARGON2_OK ? NULL : "argon2id derivation failed";
        }
        case DORADO_KDF_SCRYPT: {
            uint64_t n = (uint64_t)1 << p->log_n;
            /* Size maxmem to the parameters; this only gates the computation. */
            uint64_t maxmem = (uint64_t)128 * p->r * (n + p->p + 2) + (1u << 20);
            if (EVP_PBE_scrypt((const char *)password, password_len, salt, salt_len, n, p->r, p->p, maxmem, out,
                               out_len) != 1) {
                return "scrypt derivation failed";
            }
            return NULL;
        }
        case DORADO_KDF_PBKDF2: {
            if (PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len, salt, (int)salt_len, (int)p->rounds,
                                  EVP_sha256(), (int)out_len, out) != 1) {
                return "pbkdf2 derivation failed";
            }
            return NULL;
        }
        default:
            return "unknown kdf kind";
    }
}

const char *dorado_kdf_validate(const dorado_kdf_params *p) {
    /* Out-of-range cost parameters are the params class (see engine.h). */
    switch (p->kind) {
        case DORADO_KDF_ARGON2ID:
            if (p->m_cost > (1u << 21) || p->t_cost > 64 || p->p_cost > 16) {
                return dorado_err_params;
            }
            return NULL;
        case DORADO_KDF_SCRYPT:
            if (p->log_n > 21 || p->r > 32 || p->p > 16) {
                return dorado_err_params;
            }
            return NULL;
        case DORADO_KDF_PBKDF2:
            if (p->rounds > 50000000u) {
                return dorado_err_params;
            }
            return NULL;
        default:
            return dorado_err_params;
    }
}

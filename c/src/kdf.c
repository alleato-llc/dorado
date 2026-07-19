#include "kdf.h"

#include <argon2.h>
#include <openssl/evp.h>
#include <string.h>

#include "dorado/blake3.h"
#include "dorado/skein.h"

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

/* Fixed prefix domain-separating derive-from-key's keyed hashing from every
 * other keyed use in the engine ("DRDOrawE"/"DRDOrawM" in the raw-key split,
 * "DRDOchnk"/"DRDOrwFr" in the frame MACs). */
static const uint8_t DERIVE_FROM_KEY_DOMAIN[8] = {'D', 'R', 'D', 'O', 'k', 'd', 'r', 'v'};

const char *dorado_kdf_derive_from_key(const uint8_t *key, size_t key_len, const char *domain, uint8_t *out,
                                       size_t out_len) {
    return dorado_kdf_derive_from_key_with(DORADO_KDF_PRF_SKEIN512, key, key_len, domain, out, out_len);
}

const char *dorado_kdf_derive_from_key_with(int prf, const uint8_t *key, size_t key_len, const char *domain,
                                            uint8_t *out, size_t out_len) {
    /* out = PRF(key, out_len, "DRDOkdrv" || domain). Uses the port's own
     * from-scratch Skein-512/BLAKE3, not the delegated password-KDF libraries;
     * streaming update(A) then update(B) equals a one-shot MAC over A || B. */
    size_t domain_len = strlen(domain);
    switch (prf) {
        case DORADO_KDF_PRF_SKEIN512: {
            dorado_skein512 s;
            dorado_skein512_init_mac(&s, key, key_len, out_len);
            dorado_skein512_update(&s, DERIVE_FROM_KEY_DOMAIN, sizeof DERIVE_FROM_KEY_DOMAIN);
            dorado_skein512_update(&s, (const uint8_t *)domain, domain_len);
            dorado_skein512_finalize(&s, out);
            return NULL;
        }
        case DORADO_KDF_PRF_BLAKE3: {
            /* BLAKE3's keyed mode is defined only for a 256-bit key. */
            if (key_len != 32) {
                return dorado_err_params;
            }
            dorado_blake3 h;
            dorado_blake3_init_keyed(&h, key);
            dorado_blake3_update(&h, DERIVE_FROM_KEY_DOMAIN, sizeof DERIVE_FROM_KEY_DOMAIN);
            dorado_blake3_update(&h, (const uint8_t *)domain, domain_len);
            dorado_blake3_finalize(&h, out, out_len);
            return NULL;
        }
        default:
            return dorado_err_params;
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
            /* Zero rounds would "derive" an all-zero key without error. */
            if (p->rounds == 0 || p->rounds > 50000000u) {
                return dorado_err_params;
            }
            return NULL;
        default:
            return dorado_err_params;
    }
}

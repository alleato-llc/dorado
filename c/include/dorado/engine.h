/* The dorado authenticated password container: streaming encrypt/decrypt/inspect
 * and raw CTR, over the from-scratch Threefish cipher. The on-disk format is
 * byte-for-byte cross-compatible with the Rust reference and the other ports.
 * Functions return NULL on success or a static error message. Educational and
 * unaudited. */
#ifndef DORADO_ENGINE_H
#define DORADO_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Sentinel error strings the engine returns BY IDENTITY so a caller can classify a
 * failure by pointer comparison and still print the (human-readable) text. The three
 * classes are stable:
 *   - dorado_err_auth: authentication failed. Wrong password, corruption, and
 *     tampering are deliberately merged into this one value and are indistinguishable.
 *   - dorado_err_malformed: the input is not a well-formed container (bad magic,
 *     unsupported version, unknown id, truncated/short frame, inconsistent framing).
 *   - dorado_err_params: invalid parameters (bad chunk size, oversized label,
 *     unknown variant, out-of-range KDF cost).
 * A caller can do `if (err == dorado_err_auth) ...`. Other failures (out of memory,
 * I/O, RNG) still return their own literals and are not in these classes. */
extern const char *const dorado_err_auth;
extern const char *const dorado_err_malformed;
extern const char *const dorado_err_params;

/* MAC ids (on-disk header values). */
enum {
    DORADO_MAC_HMAC = 1,
    DORADO_MAC_SKEIN = 2,
    DORADO_MAC_BLAKE3 = 3,
};

/* KDF ids (on-disk header values). */
enum {
    DORADO_KDF_ARGON2ID = 1,
    DORADO_KDF_SCRYPT = 2,
    DORADO_KDF_PBKDF2 = 3,
};

#define DORADO_DEFAULT_CHUNK_BYTES (64u * 1024u)
#define DORADO_MAX_LABEL_LEN 4096

typedef struct {
    int kind;
    uint32_t m_cost; /* argon2id: memory in KiB */
    uint32_t t_cost; /* argon2id: iterations */
    uint32_t p_cost; /* argon2id: lanes */
    uint8_t log_n;   /* scrypt: log2(N) */
    uint32_t r;      /* scrypt: block factor */
    uint32_t p;      /* scrypt: parallelism */
    uint32_t rounds; /* pbkdf2: iterations */
    uint8_t prf;     /* pbkdf2: PRF id (1 = HMAC-SHA256) */
} dorado_kdf_params;

dorado_kdf_params dorado_kdf_argon2id(uint32_t m_cost_kib, uint32_t t_cost, uint32_t p_cost);
dorado_kdf_params dorado_kdf_scrypt(uint8_t log_n, uint32_t r, uint32_t p);
dorado_kdf_params dorado_kdf_pbkdf2(uint32_t rounds);

typedef struct {
    int variant;
    dorado_kdf_params kdf;
    int mac;
    uint8_t tweak[16];
    uint32_t chunk_size;
    const uint8_t *label;
    size_t label_len;
} dorado_options;

/* Threefish-256, Argon2id, Skein-512 MAC, 64 KiB chunks, no label. */
dorado_options dorado_default_options(void);

typedef struct {
    int version;
    int variant;
    int mac;
    dorado_kdf_params kdf;
    uint32_t chunk_size;
    size_t salt_len;
    uint8_t tweak[16];
    uint8_t label[DORADO_MAX_LABEL_LEN];
    size_t label_len;
} dorado_container_info;

/* Streaming over FILE* in constant memory. Return NULL on success. */
const char *dorado_encrypt_password_stream(const uint8_t *password, size_t password_len, const dorado_options *opts,
                                           FILE *in, FILE *out);
/* expected_label may be NULL (no label check). */
const char *dorado_decrypt_password_stream(const uint8_t *password, size_t password_len, const uint8_t *expected_label,
                                           size_t expected_label_len, FILE *in, FILE *out);
const char *dorado_raw_ctr_stream(int variant, const uint8_t *key, const uint8_t *tweak, const uint8_t *iv, FILE *in,
                                  FILE *out);
const char *dorado_inspect_stream(FILE *in, dorado_container_info *info);

/* In-memory wrappers. On success they malloc *out (caller frees) and set *out_len. */
const char *dorado_encrypt_password(const uint8_t *password, size_t password_len, const dorado_options *opts,
                                    const uint8_t *plaintext, size_t plaintext_len, uint8_t **out, size_t *out_len);
const char *dorado_decrypt_password(const uint8_t *password, size_t password_len, const uint8_t *expected_label,
                                    size_t expected_label_len, const uint8_t *data, size_t data_len, uint8_t **out,
                                    size_t *out_len);
const char *dorado_inspect(const uint8_t *data, size_t data_len, dorado_container_info *info);

#endif /* DORADO_ENGINE_H */

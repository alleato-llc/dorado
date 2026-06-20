/* Internal: the on-disk container header (marshal + streaming read). */
#ifndef DORADO_FORMAT_H
#define DORADO_FORMAT_H

#include <stdio.h>

#include "dorado/engine.h"

#define DORADO_MAGIC "DRDO"
#define DORADO_VERSION 4
/* DORADO_MAX_CHUNK_BYTES is the HARD CEILING (1 GiB) on the chunk size this build
 * will ever accept; DORADO_DEFAULT_MAX_CHUNK_BYTES (64 MiB) is the default accepted
 * cap. The effective cap (see dorado_effective_max_chunk_bytes) can be tightened
 * below the default via the DORADO_MAX_CHUNK_BYTES env var but never raised past the
 * hard ceiling. The wire format is unchanged: chunk_size is still a u32 on disk; this
 * only bounds what we are willing to allocate when reading an untrusted header. */
#define DORADO_MAX_CHUNK_BYTES (1u << 30)
#define DORADO_DEFAULT_MAX_CHUNK_BYTES (64u * 1024 * 1024)
#define DORADO_MAC_KEY_LEN 32
#define DORADO_TAG_LEN 32
#define DORADO_HEADER_MAX_BYTES 8192

typedef struct {
    int version;
    int variant;
    dorado_kdf_params kdf;
    int mac;
    uint32_t chunk_size;
    uint8_t salt[256];
    size_t salt_len;
    uint8_t tweak[16];
    uint8_t iv[128];
    uint8_t label[DORADO_MAX_LABEL_LEN];
    size_t label_len;
} dorado_header;

/* Serialize h into out (which must hold DORADO_HEADER_MAX_BYTES). Returns length. */
size_t dorado_format_marshal(const dorado_header *h, uint8_t *out);

/* Read a header from in, leaving it at the first frame. NULL or a static error. */
const char *dorado_format_read(FILE *in, dorado_header *h);

/* Read exactly n bytes; returns 1 on success, 0 at end of input / short read. */
int dorado_read_full(FILE *in, uint8_t *buf, size_t n);

/* Pure helper (testable without the environment): parse a chunk-size cap from a
 * string. NULL/empty/unparseable or trailing garbage or overflow -> the default cap
 * (DORADO_DEFAULT_MAX_CHUNK_BYTES). Otherwise the parsed value is clamped into
 * [1, DORADO_MAX_CHUNK_BYTES] (so it can only tighten below 1 GiB). */
uint32_t dorado_chunk_cap_from(const char *s);

/* The effective accepted chunk-size cap: dorado_chunk_cap_from(getenv("DORADO_MAX_CHUNK_BYTES")). */
uint32_t dorado_effective_max_chunk_bytes(void);

#endif /* DORADO_FORMAT_H */

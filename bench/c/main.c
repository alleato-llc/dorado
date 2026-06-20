/* C throughput runner. Times the from-scratch primitives under the uniform protocol
 * (see ../README.md) and emits one JSON line per benchmark. Links only the primitive
 * sources (no engine, so no libargon2/OpenSSL needed). */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "dorado/blake3.h"
#include "dorado/skein.h"
#include "dorado/threefish.h"

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* op kinds */
enum { OP_CTR, OP_SKEIN, OP_BLAKE3 };

static void run_op(int op, int variant, const uint8_t *key, const uint8_t *iv, uint8_t *data, size_t n,
                   uint8_t *out32) {
    if (op == OP_CTR) {
        dorado_threefish tf;
        dorado_threefish_init(&tf, variant, key, (const uint8_t[16]){0});
        dorado_ctr ctr;
        dorado_ctr_init(&ctr, &tf, iv);
        dorado_ctr_apply(&ctr, data, n);
    } else if (op == OP_SKEIN) {
        dorado_skein512_hash(32, data, n, out32);
    } else {
        dorado_blake3_hash(32, data, n, out32);
    }
}

static void bench(const char *name, int op, int variant, const uint8_t *key, const uint8_t *iv, uint8_t *data,
                  size_t n, double warmup, double measure) {
    uint8_t out32[32];
    double start = now_s();
    while (now_s() - start < warmup) {
        run_op(op, variant, key, iv, data, n, out32);
    }
    start = now_s();
    unsigned long long iters = 0;
    while (now_s() - start < measure) {
        run_op(op, variant, key, iv, data, n, out32);
        iters++;
    }
    double elapsed = now_s() - start;
    double mbps = (double)n * (double)iters / 1e6 / elapsed;
    printf("{\"impl\":\"c\",\"bench\":\"%s\",\"mbps\":%.2f,\"iters\":%llu}\n", name, mbps, iters);
}

int main(int argc, char **argv) {
    size_t n = argc > 1 ? (size_t)strtoull(argv[1], NULL, 10) : 1048576;
    double warmup = argc > 2 ? atof(argv[2]) : 0.5;
    double measure = argc > 3 ? atof(argv[3]) : 2.0;

    uint8_t *data = calloc(n, 1);
    uint8_t key[128], iv[128];
    for (int i = 0; i < 128; i++) {
        key[i] = 7;
        iv[i] = 1;
    }

    bench("threefish-256-ctr", OP_CTR, DORADO_T256, key, iv, data, n, warmup, measure);
    bench("threefish-512-ctr", OP_CTR, DORADO_T512, key, iv, data, n, warmup, measure);
    bench("threefish-1024-ctr", OP_CTR, DORADO_T1024, key, iv, data, n, warmup, measure);
    bench("skein-512", OP_SKEIN, 0, key, iv, data, n, warmup, measure);
    bench("blake3", OP_BLAKE3, 0, key, iv, data, n, warmup, measure);

    free(data);
    return 0;
}

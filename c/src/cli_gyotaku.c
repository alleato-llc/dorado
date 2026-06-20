/* The gyotaku CLI: Skein-512 file hashing, streaming in constant memory. */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dorado/skein.h"

static int digest_stream(FILE *f, size_t out_len, uint8_t *out) {
    dorado_skein512 s;
    dorado_skein512_init(&s, out_len);
    uint8_t buf[64 * 1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
        dorado_skein512_update(&s, buf, n);
    }
    if (ferror(f)) {
        return -1;
    }
    dorado_skein512_finalize(&s, out);
    return 0;
}

static void print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
}

static int fail(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    return 1;
}

int main(int argc, char **argv) {
    long bits = 256;
    int tag = 0;

    static const struct option longs[] = {
        {"bits", required_argument, 0, 'b'},
        {"tag", no_argument, 0, 't'},
        {"check", no_argument, 0, 'c'},
        {0, 0, 0, 0},
    };
    int check = 0;
    int c;
    while ((c = getopt_long(argc, argv, "c", longs, NULL)) != -1) {
        switch (c) {
            case 'b': bits = atol(optarg); break;
            case 't': tag = 1; break;
            case 'c': check = 1; break;
            default: return fail("usage: gyotaku [--bits N] [--tag] [-c] [files...]");
        }
    }

    if (check) {
        return fail("--check is not implemented in the C build");
    }
    if (bits <= 0 || bits % 8 != 0) {
        return fail("--bits must be a positive multiple of 8");
    }
    size_t out_len = (size_t)bits / 8;
    uint8_t out[1024];
    if (out_len > sizeof out) {
        return fail("--bits too large");
    }

    if (optind >= argc) {
        if (digest_stream(stdin, out_len, out) != 0) return fail("read error");
        if (tag) {
            printf("SKEIN-512 (-) = ");
            print_hex(out, out_len);
            printf("\n");
        } else {
            print_hex(out, out_len);
            printf("\n");
        }
        return 0;
    }

    int rc = 0;
    for (int i = optind; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "error: %s: cannot open\n", argv[i]);
            rc = 1;
            continue;
        }
        int e = digest_stream(f, out_len, out);
        fclose(f);
        if (e != 0) {
            fprintf(stderr, "error: %s: read error\n", argv[i]);
            rc = 1;
            continue;
        }
        if (tag) {
            printf("SKEIN-512 (%s) = ", argv[i]);
            print_hex(out, out_len);
            printf("\n");
        } else {
            print_hex(out, out_len);
            printf("  %s\n", argv[i]);
        }
    }
    return rc;
}

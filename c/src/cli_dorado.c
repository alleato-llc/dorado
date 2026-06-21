/* The dorado CLI: encrypt/decrypt/inspect, raw-key and password modes, streaming. */
#include <getopt.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dorado/engine.h"
#include "dorado/threefish.h"

#define DORADO_CLI_VERSION "0.1.0"

static void print_usage(FILE *f) {
    fprintf(f,
            "dorado %s - Threefish in CTR mode (educational, unaudited)\n"
            "\n"
            "Usage: dorado <encrypt|decrypt|inspect> [flags]\n"
            "\n"
            "Commands:\n"
            "  encrypt   Encrypt input with Threefish-CTR\n"
            "  decrypt   Decrypt input (the same operation as encrypt)\n"
            "  inspect   Show a password container's non-secret parameters\n"
            "\n"
            "Credentials (choose exactly one for encrypt/decrypt):\n"
            "  --key <hex>            Raw key as hex (requires --iv)\n"
            "  --key-file <FILE>      Read the raw key hex from a file (requires --iv)\n"
            "  --password             Derive the key from a prompted password\n"
            "  --password-stdin       Read the password from stdin (pass data via --in)\n"
            "\n"
            "Common flags:\n"
            "  --in <FILE>            Input file (default: stdin)\n"
            "  --out <FILE>           Output file (default: stdout)\n"
            "  --iv <hex>             IV for raw-key mode (block-size length)\n"
            "  --tweak <hex>          16-byte tweak (default: all zero)\n"
            "  --variant <256|512|1024>   Threefish variant (default: 256)\n"
            "  --kdf <argon2id|scrypt|pbkdf2>   Password KDF (default: argon2id)\n"
            "  --mac <skein|hmac-sha256|blake3> Container MAC (default: skein)\n"
            "  --label <text>         Bind a non-secret label (encrypt)\n"
            "  --expect-label <text>  Require a label match (decrypt)\n"
            "  --chunk-kib <N>        Chunk size in KiB (default: 64)\n"
            "\n"
            "KDF cost flags:\n"
            "  --argon2-mem-mib <N> --argon2-time <N> --argon2-par <N>\n"
            "  --scrypt-logn <N> --scrypt-r <N> --scrypt-p <N>\n"
            "  --pbkdf2-rounds <N>\n"
            "\n"
            "  -h, --help     Print this help and exit\n"
            "      --version  Print the version and exit\n",
            DORADO_CLI_VERSION);
}

/* A page-aligned, mlock'd buffer for a secret the CLI holds (the password): kept
 * out of swap, and wiped + unlocked on free. mlock failure (e.g. RLIMIT_MEMLOCK on
 * a locked-down host) is non-fatal: the buffer is still wiped on free. */
static uint8_t *secure_alloc(size_t want, size_t *cap) {
    long pg = sysconf(_SC_PAGESIZE);
    if (pg < 1) {
        pg = 4096;
    }
    size_t c = ((want + (size_t)pg - 1) / (size_t)pg) * (size_t)pg;
    void *p = NULL;
    if (posix_memalign(&p, (size_t)pg, c) != 0) {
        return NULL;
    }
    mlock(p, c); /* best-effort */
    *cap = c;
    return p;
}

static void secure_free(uint8_t *p, size_t cap) {
    if (!p) {
        return;
    }
    OPENSSL_cleanse(p, cap);
    munlock(p, cap);
    free(p);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, uint8_t *out, size_t max, size_t *out_len) {
    size_t n = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') {
            continue;
        }
        int hi = hexval(*p);
        int lo = *(p + 1) ? hexval(*(p + 1)) : -1;
        if (hi < 0 || lo < 0) {
            return -1;
        }
        if (n >= max) {
            return -1;
        }
        out[n++] = (uint8_t)((hi << 4) | lo);
        p++;
    }
    *out_len = n;
    return 0;
}

static int variant_from_str(const char *s) {
    if (strcmp(s, "256") == 0) return DORADO_T256;
    if (strcmp(s, "512") == 0) return DORADO_T512;
    if (strcmp(s, "1024") == 0) return DORADO_T1024;
    return -1;
}

static int mac_from_str(const char *s) {
    if (strcmp(s, "skein") == 0) return DORADO_MAC_SKEIN;
    if (strcmp(s, "hmac-sha256") == 0) return DORADO_MAC_HMAC;
    if (strcmp(s, "blake3") == 0) return DORADO_MAC_BLAKE3;
    return -1;
}

struct opts_t {
    const char *key, *key_file, *iv, *tweak;
    int password, password_stdin;
    const char *variant, *kdf, *mac;
    long argon2_mem, argon2_time, argon2_par, scrypt_logn, scrypt_r, scrypt_p, pbkdf2_rounds, chunk_kib;
    const char *label, *expect_label, *in_path, *out_path;
};

static size_t read_password(const struct opts_t *o, uint8_t *buf, size_t max) {
    if (o->password_stdin) {
        if (!fgets((char *)buf, (int)max, stdin)) return 0;
        size_t n = strlen((char *)buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
        return n;
    }
    char *pw = getpass("Password: ");
    size_t n = strlen(pw);
    if (n >= max) n = max - 1;
    memcpy(buf, pw, n);
    return n;
}

static int fail(const char *msg) {
    fprintf(stderr, "error: %s\n", msg);
    return 1;
}

int main(int argc, char **argv) {
    /* Top-level --help/-h/--version work with or without a subcommand, matching
     * the Rust reference. Scan all args so "dorado encrypt --help" works too. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(stdout);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("dorado %s\n", DORADO_CLI_VERSION);
            return 0;
        }
    }

    if (argc < 2) return fail("usage: dorado <encrypt|decrypt|inspect> [flags]");
    const char *command = argv[1];

    struct opts_t o = {0};
    o.tweak = "00000000000000000000000000000000";
    o.variant = "256";
    o.kdf = "argon2id";
    o.mac = "skein";
    o.argon2_mem = 64;
    o.argon2_time = 3;
    o.argon2_par = 1;
    o.scrypt_logn = 15;
    o.scrypt_r = 8;
    o.scrypt_p = 1;
    o.pbkdf2_rounds = 600000;
    o.chunk_kib = 64;

    enum {
        K = 1000, KF, IV, TW, PW, PWS, VAR, KDF, MAC, AM, AT, AP, SL, SR, SP, PR, CK, LB, EL, IN, OUT
    };
    static const struct option longs[] = {
        {"key", required_argument, 0, K},          {"key-file", required_argument, 0, KF},
        {"iv", required_argument, 0, IV},          {"tweak", required_argument, 0, TW},
        {"password", no_argument, 0, PW},          {"password-stdin", no_argument, 0, PWS},
        {"variant", required_argument, 0, VAR},    {"kdf", required_argument, 0, KDF},
        {"mac", required_argument, 0, MAC},        {"argon2-mem-mib", required_argument, 0, AM},
        {"argon2-time", required_argument, 0, AT}, {"argon2-par", required_argument, 0, AP},
        {"scrypt-logn", required_argument, 0, SL}, {"scrypt-r", required_argument, 0, SR},
        {"scrypt-p", required_argument, 0, SP},    {"pbkdf2-rounds", required_argument, 0, PR},
        {"chunk-kib", required_argument, 0, CK},   {"label", required_argument, 0, LB},
        {"expect-label", required_argument, 0, EL}, {"in", required_argument, 0, IN},
        {"out", required_argument, 0, OUT},        {0, 0, 0, 0},
    };
    optind = 2;
    int c;
    while ((c = getopt_long(argc, argv, "", longs, NULL)) != -1) {
        switch (c) {
            case K: o.key = optarg; break;
            case KF: o.key_file = optarg; break;
            case IV: o.iv = optarg; break;
            case TW: o.tweak = optarg; break;
            case PW: o.password = 1; break;
            case PWS: o.password_stdin = 1; break;
            case VAR: o.variant = optarg; break;
            case KDF: o.kdf = optarg; break;
            case MAC: o.mac = optarg; break;
            case AM: o.argon2_mem = atol(optarg); break;
            case AT: o.argon2_time = atol(optarg); break;
            case AP: o.argon2_par = atol(optarg); break;
            case SL: o.scrypt_logn = atol(optarg); break;
            case SR: o.scrypt_r = atol(optarg); break;
            case SP: o.scrypt_p = atol(optarg); break;
            case PR: o.pbkdf2_rounds = atol(optarg); break;
            case CK: o.chunk_kib = atol(optarg); break;
            case LB: o.label = optarg; break;
            case EL: o.expect_label = optarg; break;
            case IN: o.in_path = optarg; break;
            case OUT: o.out_path = optarg; break;
            default: return fail("unknown flag");
        }
    }

    FILE *in = o.in_path ? fopen(o.in_path, "rb") : stdin;
    if (!in) return fail("cannot open input");
    FILE *out = o.out_path ? fopen(o.out_path, "wb") : stdout;
    if (!out) return fail("cannot open output");

    int rc = 0;
    const char *err = NULL;
    uint8_t *secpw = NULL; /* mlock'd password buffer, freed at done: */
    size_t secpw_cap = 0;

    if (strcmp(command, "inspect") == 0) {
        dorado_container_info info;
        err = dorado_inspect_stream(in, &info);
        if (!err) {
            const char *vn = info.variant == DORADO_T256 ? "Threefish-256"
                             : info.variant == DORADO_T512 ? "Threefish-512" : "Threefish-1024";
            const char *mn = info.mac == DORADO_MAC_SKEIN ? "Skein-512"
                             : info.mac == DORADO_MAC_HMAC ? "HMAC-SHA256" : "BLAKE3 (keyed)";
            printf("format:   dorado password container (DRDO v%d)\n", info.version);
            printf("variant:  %s\n", vn);
            if (info.kdf.kind == DORADO_KDF_ARGON2ID)
                printf("kdf:      Argon2id (memory %u KiB, iterations %u, lanes %u)\n", info.kdf.m_cost,
                       info.kdf.t_cost, info.kdf.p_cost);
            else if (info.kdf.kind == DORADO_KDF_SCRYPT)
                printf("kdf:      scrypt (log2(N) %u, r %u, p %u)\n", info.kdf.log_n, info.kdf.r, info.kdf.p);
            else
                printf("kdf:      PBKDF2-HMAC-SHA256 (rounds %u)\n", info.kdf.rounds);
            printf("mac:      %s\n", mn);
            printf("chunk:    %u bytes\n", info.chunk_size);
            printf("salt:     %zu bytes\n", info.salt_len);
            printf("tweak:    ");
            for (int i = 0; i < 16; i++) printf("%02x", info.tweak[i]);
            printf("\nlabel:    %.*s\n", info.label_len ? (int)info.label_len : 6,
                   info.label_len ? (char *)info.label : "(none)");
        }
    } else if (strcmp(command, "encrypt") == 0 || strcmp(command, "decrypt") == 0) {
        int encrypt = strcmp(command, "encrypt") == 0;
        int creds = (o.key != NULL) + (o.key_file != NULL) + o.password + o.password_stdin;
        if (creds != 1) {
            rc = fail("provide exactly one of --key, --key-file, --password, --password-stdin");
            goto done;
        }
        uint8_t tweak[16];
        size_t tweak_len;
        if (parse_hex(o.tweak, tweak, 16, &tweak_len) != 0 || tweak_len != 16) {
            rc = fail("--tweak must be 16 bytes of hex");
            goto done;
        }
        if (o.key || o.key_file) {
            char keyhex_buf[512];
            const char *keyhex = o.key;
            if (o.key_file) {
                FILE *kf = fopen(o.key_file, "r");
                if (!kf) {
                    rc = fail("cannot open key file");
                    goto done;
                }
                size_t kn = fread(keyhex_buf, 1, sizeof keyhex_buf - 1, kf);
                keyhex_buf[kn] = 0;
                fclose(kf);
                keyhex = keyhex_buf;
            }
            uint8_t key[128];
            size_t key_len;
            if (parse_hex(keyhex, key, 128, &key_len) != 0) {
                rc = fail("invalid key hex");
                goto done;
            }
            int variant = key_len == 32 ? DORADO_T256 : key_len == 64 ? DORADO_T512 : key_len == 128 ? DORADO_T1024 : -1;
            if (variant < 0) {
                rc = fail("key must be 32, 64, or 128 bytes");
                goto done;
            }
            if (!o.iv) {
                rc = fail("--iv is required with --key/--key-file");
                goto done;
            }
            uint8_t iv[128];
            size_t iv_len;
            if (parse_hex(o.iv, iv, 128, &iv_len) != 0 || (int)iv_len != dorado_variant_len(variant)) {
                rc = fail("--iv length must match the variant block size");
                goto done;
            }
            err = dorado_raw_ctr_stream(variant, key, tweak, iv, in, out);
            OPENSSL_cleanse(key, sizeof key);
        } else {
            if (o.iv) {
                rc = fail("--iv is not used in password mode; the IV is generated and stored");
                goto done;
            }
            if (o.password_stdin && !o.in_path) {
                rc = fail("with --password-stdin, pass the data via --in");
                goto done;
            }
            secpw = secure_alloc(1024, &secpw_cap);
            if (!secpw) {
                rc = fail("out of memory");
                goto done;
            }
            uint8_t *password = secpw;
            size_t pw_len = read_password(&o, password, secpw_cap);
            if (encrypt) {
                int variant = variant_from_str(o.variant);
                int mac = mac_from_str(o.mac);
                if (variant < 0 || mac < 0) {
                    rc = fail("unknown --variant or --mac");
                    goto done;
                }
                dorado_options opts = {0};
                opts.variant = variant;
                opts.mac = mac;
                memcpy(opts.tweak, tweak, 16);
                opts.chunk_size = (uint32_t)(o.chunk_kib * 1024);
                if (strcmp(o.kdf, "argon2id") == 0)
                    opts.kdf = dorado_kdf_argon2id((uint32_t)(o.argon2_mem * 1024), (uint32_t)o.argon2_time,
                                                   (uint32_t)o.argon2_par);
                else if (strcmp(o.kdf, "scrypt") == 0)
                    opts.kdf = dorado_kdf_scrypt((uint8_t)o.scrypt_logn, (uint32_t)o.scrypt_r, (uint32_t)o.scrypt_p);
                else if (strcmp(o.kdf, "pbkdf2") == 0)
                    opts.kdf = dorado_kdf_pbkdf2((uint32_t)o.pbkdf2_rounds);
                else {
                    rc = fail("unknown --kdf");
                    goto done;
                }
                if (o.label) {
                    opts.label = (const uint8_t *)o.label;
                    opts.label_len = strlen(o.label);
                }
                err = dorado_encrypt_password_stream(password, pw_len, &opts, in, out);
            } else {
                const uint8_t *exp = o.expect_label ? (const uint8_t *)o.expect_label : NULL;
                size_t exp_len = o.expect_label ? strlen(o.expect_label) : 0;
                err = dorado_decrypt_password_stream(password, pw_len, exp, exp_len, in, out);
            }
        }
    } else {
        rc = fail("usage: dorado <encrypt|decrypt|inspect> [flags]");
        goto done;
    }

    if (err) rc = fail(err);

done:
    secure_free(secpw, secpw_cap);
    if (in != stdin) fclose(in);
    if (out != stdout) fclose(out);
    return rc;
}

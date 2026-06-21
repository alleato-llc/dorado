/* libFuzzer harness for the dorado decrypt path. Feeds arbitrary bytes to the
 * in-memory decrypt entrypoint; the fuzzer drives coverage of the header parser and
 * the framing/MAC loop. Built with sanitizers via `make fuzz`:
 *
 *   make fuzz && ./fuzz/fuzz_decrypt           # run with libFuzzer defaults
 *   ./fuzz/fuzz_decrypt -max_total_time=60     # time-boxed run
 *   ./fuzz/fuzz_decrypt corpus/                # replay a corpus directory
 *
 * Needs a clang with libFuzzer (clang -fsanitize=fuzzer). On success the engine
 * mallocs *out; we free it. The KDF cost is whatever the input header asks for, so a
 * dictionary/seed that uses PBKDF2 with low rounds keeps iterations fast; libFuzzer
 * will mostly hit the parse path and reject before any KDF runs anyway. */
#include <stdint.h>
#include <stdlib.h>

#include "dorado/engine.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t pw[] = "pw-cross";
    uint8_t *out = NULL;
    size_t out_len = 0;
    const char *err = dorado_decrypt_password(pw, sizeof pw - 1, NULL, 0, data, size, &out, &out_len);
    if (err == NULL) {
        free(out);
    }
    return 0;
}

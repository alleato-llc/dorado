# dorado (C): a from-scratch Threefish cipher + authenticated container.
# Argon2 comes from the system libargon2, scrypt/PBKDF2/HMAC from OpenSSL, both via
# pkg-config. Install them first:
#   macOS:  brew install argon2 openssl@3
#   Debian: apt-get install -y libargon2-dev libssl-dev pkg-config

CC ?= cc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra
# glibc hides the POSIX/GNU declarations this port uses (fmemopen,
# open_memstream, getrandom) under strict -std=c17; _DEFAULT_SOURCE restores
# them (a no-op on macOS, which exposes everything by default). Without it the
# functions are implicitly declared as returning int, which truncates the
# returned FILE * and crashes at run time on Linux. The -Werror pair makes any
# future missed declaration a compile error instead of that silent crash.
CFLAGS += -Iinclude -D_DEFAULT_SOURCE \
  -Werror=implicit-function-declaration -Werror=int-conversion

# On macOS the Homebrew .pc files are not on the default pkg-config path.
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  export PKG_CONFIG_PATH := $(shell brew --prefix argon2 2>/dev/null)/lib/pkgconfig:$(shell brew --prefix openssl@3 2>/dev/null)/lib/pkgconfig:$(PKG_CONFIG_PATH)
endif

DEPS := libargon2 openssl
PKG_CFLAGS := $(shell pkg-config --cflags $(DEPS))
PKG_LIBS := $(shell pkg-config --libs $(DEPS))

LIB_SRCS := src/threefish.c src/skein.c src/blake3.c src/format.c src/kdf.c src/mac.c src/engine.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

# Sanitizers for the test binary. `make test` is plain (no sanitizers); `make test
# SAN=1` (or `make test-san`) builds the test AND the library sources together with
# AddressSanitizer + UndefinedBehaviorSanitizer so the whole construction (not just
# the test translation unit) is instrumented. SAN only affects the test target, so
# the shipped library and CLIs keep their normal flags. On Linux (CI) the combined
# ASan+UBSan link works; on macOS the combination can be finicky to link, so if it
# fails there try `make test-san SAN_FLAGS='-fsanitize=address -g'` (ASan alone).
SAN ?=
SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -g

all: dorado gyotaku

%.o: %.c
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

libdorado.a: $(LIB_OBJS)
	ar rcs $@ $^

dorado: src/cli_dorado.o libdorado.a
	$(CC) $(CFLAGS) $< -L. -ldorado $(PKG_LIBS) -o $@

gyotaku: src/cli_gyotaku.o libdorado.a
	$(CC) $(CFLAGS) $< -L. -ldorado $(PKG_LIBS) -o $@

tests/test_dorado: tests/test_dorado.c libdorado.a
	$(CC) $(CFLAGS) $(PKG_CFLAGS) $< -L. -ldorado $(PKG_LIBS) -o $@

# Plain `make test` runs the unsanitized binary; `make test SAN=1` runs the
# sanitized one (the same thing as `make test-san`).
ifeq ($(SAN),1)
test: test-san
else
test: tests/test_dorado
	./tests/test_dorado
endif

# Sanitized test binary: compile the test together with the library sources (not the
# prebuilt archive) under ASan/UBSan so the whole construction is instrumented.
tests/test_dorado_san: tests/test_dorado.c $(LIB_SRCS)
	$(CC) $(CFLAGS) $(SAN_FLAGS) $(PKG_CFLAGS) $^ $(PKG_LIBS) -o $@

test-san: tests/test_dorado_san
	./tests/test_dorado_san

# Prove the primitives (Threefish/CTR, Skein, BLAKE3) build with no hosted runtime:
# -ffreestanding compiles them with no OS and no allocator, depending only on the
# freestanding headers plus compiler-provided memcpy/memset (which any bare-metal
# target supplies at link time). The engine, which needs malloc/FILE/libargon2/
# OpenSSL, is intentionally excluded; this mirrors the Rust port's bare-metal cipher
# crate (the cipher is portable; the construction is not).
FREESTANDING_CFLAGS := -std=c17 -ffreestanding -Wall -Wextra -Iinclude
freestanding:
	@for f in threefish skein blake3; do \
		$(CC) $(FREESTANDING_CFLAGS) -c src/$$f.c -o /dev/null && echo "  $$f.c: freestanding OK" || exit 1; \
	done

# Same check, but genuinely cross-compiled to a bare-metal ARM target (Cortex-M4
# Thumb by default), so the primitives are proven to build for a no-OS machine that
# is not the host, not just with -ffreestanding on the host compiler. Needs an ARM
# bare-metal toolchain (Debian: apt-get install -y gcc-arm-none-eabi). Override
# CROSS_CC / CROSS_FLAGS for a different toolchain or CPU. `make freestanding`
# above stays host-only and needs no cross toolchain.
CROSS_CC ?= arm-none-eabi-gcc
CROSS_FLAGS ?= -mcpu=cortex-m4 -mthumb
freestanding-arm:
	@for f in threefish skein blake3; do \
		$(CROSS_CC) $(CROSS_FLAGS) $(FREESTANDING_CFLAGS) -c src/$$f.c -o /dev/null && echo "  $$f.c: freestanding ($(CROSS_CC)) OK" || exit 1; \
	done

# libFuzzer harness for the decrypt path. Needs a clang with libFuzzer. The library
# sources are compiled in (not the archive) so they are instrumented too. Run it as
# `./fuzz/fuzz_decrypt` (libFuzzer defaults) or with `-max_total_time=N`.
FUZZ_CC ?= clang
fuzz: fuzz/fuzz_decrypt
fuzz/fuzz_decrypt: fuzz/fuzz_decrypt.c $(LIB_SRCS)
	$(FUZZ_CC) $(CFLAGS) -g -fsanitize=fuzzer,address,undefined $(PKG_CFLAGS) $^ $(PKG_LIBS) -o $@

clean:
	rm -f $(LIB_OBJS) src/cli_dorado.o src/cli_gyotaku.o libdorado.a dorado gyotaku \
		tests/test_dorado tests/test_dorado_san fuzz/fuzz_decrypt

.PHONY: all test test-san fuzz freestanding freestanding-arm clean

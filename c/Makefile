# dorado (C): a from-scratch Threefish cipher + authenticated container.
# Argon2 comes from the system libargon2, scrypt/PBKDF2/HMAC from OpenSSL, both via
# pkg-config. Install them first:
#   macOS:  brew install argon2 openssl@3
#   Debian: apt-get install -y libargon2-dev libssl-dev pkg-config

CC ?= cc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra
CFLAGS += -Iinclude

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

test: tests/test_dorado
	./tests/test_dorado

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

clean:
	rm -f $(LIB_OBJS) src/cli_dorado.o src/cli_gyotaku.o libdorado.a dorado gyotaku tests/test_dorado

.PHONY: all test freestanding clean

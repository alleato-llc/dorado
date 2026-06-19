# dorado (Go)

A Go port of dorado, matching the Rust implementation in `../rust`. Same
from-scratch primitives verified against the same official vectors, the same
on-disk container format (so the two are byte-for-byte cross-compatible), and the
same construction. The GUI is intentionally not ported.

Module path: `github.com/alleato-llc/dorado/go`.

## Layout

- `threefish/` — Threefish 256/512/1024, verified against the official KAT
  vectors. Implements `crypto/cipher.Block`, so `cipher.NewCTR` and the rest of
  the standard library's modes work over it.
- `chacha/`, `poly1305/`, `chacha20poly1305/` — the ChaCha20-Poly1305 family
  (RFC 8439). The AEAD has allocation-free `*InPlace` forms and implements
  `crypto/cipher.AEAD`.
- `skein/`, `blake3/` — the hashers, implementing `hash.Hash`. BLAKE3 uses the
  streaming chunk-stack algorithm and is differential-tested against
  `lukechampine.com/blake3`.
- `engine/` — the construction: KDFs (`golang.org/x/crypto` argon2/scrypt, stdlib
  pbkdf2), the chunked authenticated container over `io.Reader`/`io.Writer`, the
  MAC menu, v4 label binding, raw CTR, and inspect.
- `cmd/dorado`, `cmd/gyotaku` — the two CLIs.

## Differences from the Rust version

What the Rust port has that Go cannot match: the `no_std`/bare-metal levels (Go
always links its runtime) and strong zeroization (Go's GC offers no destructor or
copy guarantee). Where Go is cleaner: ecosystem interop is via the standard
library interfaces (`cipher.Block`, `cipher.AEAD`, `hash.Hash`) rather than
optional traits, and the streaming container is idiomatic with `io`.

## Build and test

```
go test ./...                 # all packages
go build ./cmd/dorado         # the CLI
go build ./cmd/gyotaku        # the Skein hashing tool
```

Educational and unaudited, like the rest of dorado.

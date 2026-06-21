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
- `skein/`, `blake3/` — the hashers, implementing `hash.Hash`. BLAKE3 uses the
  streaming chunk-stack algorithm and is differential-tested against
  `lukechampine.com/blake3`.
- `engine/` — the construction: KDFs (`golang.org/x/crypto` argon2/scrypt, stdlib
  pbkdf2), the chunked authenticated container over `io.Reader`/`io.Writer`, the
  MAC menu, v4 label binding, raw CTR, and inspect.
- `cmd/dorado`, `cmd/gyotaku` — the two CLIs.

## Differences from the Rust version

What the Rust port has that Go cannot match: the `no_std`/bare-metal levels (Go
always links its runtime) and a non-elidable, language-guaranteed wipe (Rust's
`zeroize` uses volatile writes the compiler may not drop; Go has no equivalent
guarantee). Where Go is cleaner: ecosystem interop is via the standard library
interfaces (`cipher.Block`, `cipher.AEAD`, `hash.Hash`) rather than optional traits,
and the streaming container is idiomatic with `io`.

## Secret handling

The engine wipes the derived keys and the cipher's expanded key schedule after use
(a clear plus `runtime.KeepAlive` to defeat dead-store elimination; Go's heap is
non-moving, so the slice is not relocated; the key schedule is reached through a
`Zeroize()` method on the `threefish` type via a type assertion). The `dorado` CLI
holds the password in an off-heap, `mlock`'d buffer (the `secure` package: anonymous
`mmap` memory kept out of swap and not subject to growable-stack copies, wiped and
unmapped on free). On non-Unix platforms the `secure` buffer falls back to a wiped
heap slice. This reduces exposure but is not a guarantee: the password still transits
the Go heap and may arrive as an immutable string first, `mlock` is best-effort, and
the `KeepAlive` clear is a convention rather than a non-elidable wipe the way Rust's
`zeroize` or C's `OPENSSL_cleanse` are. See `secure/secure.go` for the full caveats.

## Build and test

```
go test ./...                 # all packages
go build ./cmd/dorado         # the CLI
go build ./cmd/gyotaku        # the Skein hashing tool
```

Educational and unaudited, like the rest of dorado.

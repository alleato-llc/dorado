# dorado (Go)

A Go port of dorado, matching the Rust reference in `../rust`. Same from-scratch
primitives verified against the same official vectors, the same on-disk container
format (so the two are byte-for-byte cross-compatible), and the same construction.
An SDK plus the two command-line tools; the GUI is intentionally not ported.

Module path: `github.com/alleato-llc/dorado/go`. Educational and unaudited.

## Layout

- `threefish/` — Threefish 256/512/1024, verified against the official KAT
  vectors. Implements `crypto/cipher.Block`, so `cipher.NewCTR` and the rest of
  the standard library's modes work over it.
- `skein/`, `blake3/` — the hashers, implementing `hash.Hash`. BLAKE3 uses the
  streaming chunk-stack algorithm and is differential-tested against
  `lukechampine.com/blake3`.
- `engine/` — the construction: both standard forms of key derivation
  (`DeriveFromPassword`, the slow password stretch over `golang.org/x/crypto`
  argon2/scrypt and stdlib pbkdf2, and `DeriveFromKey`/`DeriveFromKeyWith`, the
  fast domain-separated fan-out of an already-strong key, Skein-512 by default or
  keyed BLAKE3 via `KDFPrf`), the chunked authenticated container over
  `io.Reader`/`io.Writer`, the MAC menu, v4 label binding, raw CTR (bare and
  authenticated), and inspect.
- `cmd/dorado`, `cmd/gyotaku` — the two CLIs.

## Build

```
go build ./cmd/dorado     # the dorado password tool
go build ./cmd/gyotaku    # the Skein hashing tool
```

## Use

SDK (the `engine` package):

```go
import "github.com/alleato-llc/dorado/go/engine"

opts := engine.DefaultOptions()                          // Threefish-256, Argon2id, Skein-512
ct, err := engine.EncryptPasswordBytes(password, opts, plaintext)
pt, err := engine.DecryptPasswordBytes(password, ct)
// or stream in constant memory:
//   engine.EncryptPasswordStream(password, opts, r, w)
//   engine.DecryptPasswordStream(password, r, w)
```

CLI:

```
./dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
./gyotaku --bits 256 notes.txt
```

Raw-key mode (`--key`/`--key-file` with `--iv`) is authenticated by default,
matching the Rust CLI: encrypt-then-MAC output (larger than the input by the
per-chunk framing and tag; `--mac` and `--chunk-kib` apply), rejected on decrypt
if tampered, corrupted, or decrypted with the wrong key. `--unauthenticated`
opts back into bare CTR (output length exactly equals input length, no tamper
detection), an expert opt-out for interop and composition. Password mode is
always authenticated and rejects the flag.

## Testing

```
go test ./...     # all packages: KATs, every KDF/MAC/variant, the security
                  # properties (truncation, tampering, reordering), and the
                  # KDF-cost bounds
```

CI additionally runs `go test -race` and `govulncheck` on Go 1.25.

## Cross-compatibility

The container bytes are identical to the other eight implementations: each can
decrypt the others' `.mahi` files. The suite decrypts committed fixtures produced
by the Rust reference (in `engine/testdata/`) covering every KDF, MAC, and variant
plus a labeled and a multi-frame file; the reverse direction is covered by a
committed fixture in the Rust suite (the Rust CLI decrypts a container encrypted
by this port).

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

## Differences from the Rust reference

What the Rust port has that Go cannot match: the `no_std`/bare-metal levels (Go
always links its runtime) and a non-elidable, language-guaranteed wipe (Rust's
`zeroize` uses volatile writes the compiler may not drop; Go has no equivalent
guarantee). Where Go is cleaner: ecosystem interop is via the standard library
interfaces (`cipher.Block`, `cipher.AEAD`, `hash.Hash`) rather than optional traits,
and the streaming container is idiomatic with `io`.

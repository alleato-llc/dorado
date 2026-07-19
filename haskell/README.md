# dorado (Haskell)

A Haskell port of dorado, matching the Rust reference (`../rust`) and the other
ports. Same from-scratch primitives against the same official vectors, the same
on-disk container format (byte-for-byte cross-compatible), the same CLIs, and the
same streaming construction. An SDK plus the two command-line tools.

Like the Rust reference, it **streams** over `Handle`s in constant memory, so inputs
larger than RAM are fine; in-memory `ByteString` wrappers are provided. It is strict
throughout (no laziness in the hot path): the primitive cores run in `Control.Monad.ST`
over unboxed mutable arrays (`STUArray`) behind pure `runST` functions, and `IO` is
reserved for the streaming boundary. Haskell's native `Word64` makes the 64-bit ARX
direct (no big-integer workaround). Educational and unaudited; for real data prefer a
vetted library.

## Layout

- `src/Dorado/Threefish.hs`, `Skein.hs`, `Blake3.hs`, `Sha256.hs` — the from-scratch
  primitives (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3, and SHA-256 + HMAC),
  verified against the same vectors as the Rust reference. Unlike the other ports,
  SHA-256/HMAC-SHA256 are also implemented from scratch here rather than taken from a
  standard library.
- `src/Dorado/Kdf.hs`, `Mac.hs`, `Format.hs`, `Engine.hs` — the construction: key
  derivation in both standard forms (the password KDFs delegated to `crypton`, with
  `validate` bounding untrusted cost parameters; the fast key-based
  `deriveFromKey`/`deriveFromKeyWith` fan-out built on the port's own Skein-512 and
  BLAKE3), the MAC menu, the v4 container header and the chunk-size cap, and the
  streaming password container, raw CTR (bare and authenticated), inspect, and label
  binding. The engine returns `Either String` for malformed/auth failures.
- `app/dorado/`, `app/gyotaku/` — the two CLIs.

The cipher and the Skein/BLAKE3/SHA-256 hashes are from scratch; only the password
KDFs are a dependency (`crypton`), matching the other ports' use of a KDF library.

Decryption treats the container header as untrusted input: the KDF cost parameters
are bounded (`Dorado.Kdf.validate`) and the chunk size is capped (64 MiB by default,
1 GiB hard ceiling) before any allocation or key derivation, so a crafted file
cannot demand gigabytes of memory or a multi-minute derivation. The
`DORADO_MAX_CHUNK_BYTES` environment variable can tighten the cap, never raise it
past the ceiling; the pure in-memory decrypt functions use the fixed 64 MiB default
(only the streaming `IO` forms can read the environment).

## Build

Needs GHC and Cabal (tested with GHC 9.14). `cabal` fetches `crypton`:

```
cabal build all
```

## Use

SDK (the `Dorado.Engine` module):

```haskell
import qualified Dorado.Engine as E

-- in-memory:
let opts = E.defaultOptions                          -- Threefish-256, Argon2id, Skein-512
container <- E.encryptPassword password opts tweak plaintext   -- IO (random salt + IV)
let recovered = E.decryptPassword password container           -- Either String ByteString

-- or stream over Handles in constant memory:
--   E.encryptPasswordStream opts salt tweak iv password hIn hOut
--   E.decryptPasswordStream password expectedLabel hIn hOut

-- fan an already-strong key out into independent per-purpose subkeys
-- (fast, deterministic; never pass a password here, it is not stretched):
import qualified Dorado.Kdf as Kdf
let indexKey = Kdf.deriveFromKey master "myapp/index" 32
```

CLI:

```
cabal run dorado -- encrypt --password-stdin --in notes.txt --out notes.txt.mahi
cabal run dorado -- encrypt --key <hex> --iv <hex> --in notes.txt --out notes.txt.enc
cabal run gyotaku -- --bits 256 notes.txt
```

Raw-key mode (`--key`/`--key-file`) is authenticated by default: encrypt-then-MAC,
with `--mac` and `--chunk-kib` applying, so a tampered, corrupted, or wrong-key
stream is rejected on decrypt. Pass `--unauthenticated` for bare CTR (output length
equals input length, no tamper or corruption detection), a deliberate, expert
opt-out. Password mode is always authenticated.

## Testing

```
cabal test       # KATs for every primitive, KDF vectors (RFC 7914), and the
                 # container: round-trips and cross-compat fixtures made by the Rust CLI
```

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. The test suite decrypts fixtures produced by the Rust reference (in
`test/fixtures/`) covering every KDF, MAC, and variant plus a labeled and a
multi-frame file; the reverse direction (the Rust CLI decrypting Haskell's password
and raw output, including a multi-frame streamed file) is verified during development.

## Secret handling

Caller-managed, like the Java and Python ports: secrets live in GC-managed
`ByteString`s that are not wiped, and the CLI does not `mlock` the password. This is
weaker than the Rust/C/Zig/Go ports (no non-elidable wipe, no locked memory); it is a
known limitation of this educational port, not a guarantee.

# dorado (TypeScript)

A TypeScript port of dorado, matching the Rust reference (`../rust`) and the Go
port. Same from-scratch primitives against the same official vectors, the same
on-disk container format (byte-for-byte cross-compatible), the same CLIs, and the
engine behind the in-browser demo on the landing page. An SDK plus the two Node
CLIs; no GUI.

It is isomorphic: the same code runs in Node and the browser. The 64-bit ARX in
Threefish/Skein uses `BigInt` (clarity over speed); BLAKE3 uses native 32-bit
math. Educational and unaudited; constant time is not achievable in JS, so do not
use it for real secrets.

## Layout

- `src/threefish.ts`, `skein.ts`, `blake3.ts` — the primitives, verified against
  the same vectors (BLAKE3 differential-tested against `@noble/hashes`).
- `src/engine/` — the container: both forms of key derivation (the password
  KDFs via `hash-wasm` — WASM Argon2id/scrypt/PBKDF2, isomorphic — and the
  fast key-based `deriveFromKey`/`deriveFromKeyWith` over the from-scratch
  Skein-512/BLAKE3), HMAC via Web Crypto, the MAC menu, v4 label binding,
  raw CTR (bare and authenticated), inspect.
- `src/cli/dorado.ts`, `src/cli/gyotaku.ts` — the Node CLIs.

## Build

```
npm install
npm run typecheck
```

The Node `dorado` CLI uses the WASM cipher backend (see below), which loads
`../../rust/wasm/pkg`. That build is not committed: on a fresh clone, build it
first with `cd ../rust/wasm && wasm-pack build --target nodejs` (without it the
CLI exits with an error telling you to do exactly that).

## Use

SDK (the `engine` module; `encrypt`/`decrypt` are async):

```ts
import { encryptPasswordBytes, decryptPasswordBytes, defaultOptions } from "./src/engine";

const opts = defaultOptions();                          // Threefish-256, Argon2id, Skein-512
const ct = await encryptPasswordBytes(password, opts, plaintext);
const pt = await decryptPasswordBytes(password, ct);
```

Embedders with an already-strong key can fan it out into independent
per-purpose keys with `deriveFromKey(master, "myapp/index", 32)` (one
domain-separated Skein-512 keyed hash; `deriveFromKeyWith` selects BLAKE3
instead). Never pass a password there — it does no stretching; that is
`deriveFromPassword`'s job.

CLI:

```
npm run dorado -- encrypt --password-stdin --in notes.txt --out notes.txt.mahi
npm run gyotaku -- --bits 256 notes.txt
```

Raw-key mode (`--key`/`--key-file` with `--iv`) is authenticated
(encrypt-then-MAC) by default, like the Rust CLI: `--mac` and `--chunk-kib`
apply, and a tampered, corrupted, or wrong-key stream is rejected on decrypt.
Add `--unauthenticated` to fall back to bare CTR (no authentication, output
length equals input length) — an expert opt-out, since bare CTR silently
decrypts a corrupted byte to a flipped plaintext byte with no error.

The CLI is fail-closed about secret memory: passwords and raw keys are held in
`sodium-native` secure buffers (mlock'd, off-heap, guard-paged, wiped after
use), and if `sodium-native` cannot load the CLI errors out rather than
degrading silently. Pass `--insecure-memory` to proceed anyway with ordinary
swappable heap memory; it prints a one-time warning. An interactively typed
password still transits an immutable JS string before entering the locked
buffer.

## Testing

```
npm test          # vitest: primitives (KATs) + engine (every KDF/MAC/variant and
                  # the security properties), plus a seeded decrypt fuzz/property test
```

## Cross-compatibility

The container bytes are identical to the other eight implementations: each can
decrypt the others' `.mahi` files. The suite decrypts committed fixtures produced
by the Rust reference (in `src/engine/fixtures/`) covering every KDF, MAC, and
variant plus a labeled and a multi-frame file; the reverse direction is covered
by a committed fixture in the Rust suite (the Rust CLI decrypts a container
encrypted by this port).

## Cipher backend

The engine takes a swappable `CipherBackend` (`src/engine/backend.ts`) for the
cipher and keyed hashes:

- `tsBackend` (default) is the readable pure-TS code. The test suite runs on it.
- `wasmBackend` (`src/engine/wasm-backend.ts`) runs the verified Rust cipher from
  the `../rust/wasm` build, so the secret arithmetic runs in WASM linear memory
  and the value stack instead of being scattered across short-lived `BigInt`s on
  the JS heap. The Node `dorado` CLI uses it.

The two backends are verified byte-identical by a differential test
(`src/engine/backend-diff.test.ts`), which runs where `rust/wasm/pkg` has been
built locally and skips otherwise, so cross-compatibility holds either way.
WASM removes the un-wipeable transient values, but it is not a zeroization
guarantee: a password arriving as a JS string, and copies made crossing the
JS/WASM boundary, still live on the heap. In Node, the CLI holds passwords and
raw keys in `sodium-native` secure (mlock'd, off-heap, guard-paged) buffers,
wiped after use and fail-closed if the library is unavailable (see the CLI
section); the browser has no equivalent.

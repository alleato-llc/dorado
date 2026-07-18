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
- `src/engine/` — the container: KDFs via `hash-wasm` (WASM Argon2id/scrypt/
  PBKDF2, isomorphic), HMAC via Web Crypto, the MAC menu, v4 label binding,
  raw CTR (bare and authenticated), inspect.
- `src/cli/dorado.ts`, `src/cli/gyotaku.ts` — the Node CLIs.

## Build

```
npm install
npm run typecheck
```

The Node `dorado` CLI uses the WASM cipher backend (see below); build it first
with `cd ../rust/wasm && wasm-pack build --target nodejs`.

## Use

SDK (the `engine` module; `encrypt`/`decrypt` are async):

```ts
import { encryptPasswordBytes, decryptPasswordBytes, defaultOptions } from "./src/engine";

const opts = defaultOptions();                          // Threefish-256, Argon2id, Skein-512
const ct = await encryptPasswordBytes(password, opts, plaintext);
const pt = await decryptPasswordBytes(password, ct);
```

CLI:

```
npm run dorado -- encrypt --password-stdin --in notes.txt --out notes.txt.mahi
npm run gyotaku -- --bits 256 notes.txt
```

## Testing

```
npm test          # vitest: primitives (KATs) + engine (every KDF/MAC/variant and
                  # the security properties), plus a seeded decrypt fuzz/property test
```

## Cross-compatibility

The container bytes are identical to the Rust/Go/Java/Python/C/Zig ports: each can
decrypt the others' `.mahi` files. The byte-for-byte match is verified against the
Rust CLI's output during development, across every KDF, MAC, and variant. (Unlike
the Java/Python/C/Zig ports, the TS suite does not yet embed committed Rust
fixtures.)

## Cipher backend

The engine takes a swappable `CipherBackend` (`src/engine/backend.ts`) for the
cipher and keyed hashes:

- `tsBackend` (default) is the readable pure-TS code. The test suite runs on it.
- `wasmBackend` (`src/engine/wasm-backend.ts`) runs the verified Rust cipher from
  the `../rust/wasm` build, so the secret arithmetic runs in WASM linear memory
  and the value stack instead of being scattered across short-lived `BigInt`s on
  the JS heap. The Node `dorado` CLI uses it.

Both backends produce identical output, so cross-compatibility holds either way.
WASM removes the un-wipeable transient values, but it is not a zeroization
guarantee: a password arriving as a JS string, and copies made crossing the
JS/WASM boundary, still live on the heap. In Node, secrets read as bytes are held
in `sodium-native` secure (mlock'd, no-swap) buffers and wiped after use; the
browser has no equivalent.

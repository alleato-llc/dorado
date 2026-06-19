# dorado (TypeScript)

A TypeScript port of dorado, matching the Rust (`../rust`) and Go (`../go`)
implementations. Same from-scratch primitives against the same official vectors,
the same on-disk container format (all three are byte-for-byte cross-compatible),
the same CLIs, and (to follow) an in-browser demo on the landing page. No GUI.

It is isomorphic: the same code runs in Node and the browser. The 64-bit ARX in
Threefish/Skein uses `BigInt` (clarity over speed); ChaCha20/BLAKE3 use native
32-bit math. Educational and unaudited; constant time and zeroization are not
achievable in JS, so do not use it for real secrets.

## Layout

- `src/threefish.ts`, `chacha.ts`, `poly1305.ts`, `chacha20poly1305.ts`,
  `skein.ts`, `blake3.ts` — the primitives, verified against the same vectors
  (BLAKE3 differential-tested against `@noble/hashes`).
- `src/engine/` — the container: KDFs via `hash-wasm` (WASM Argon2id/scrypt/
  PBKDF2, isomorphic), HMAC via Web Crypto, the MAC menu, v4 label binding,
  raw CTR, inspect.
- `src/cli/dorado.ts`, `src/cli/gyotaku.ts` — the Node CLIs.

## Use

```
npm install
npm test                                   # vitest (primitives + engine)
npm run typecheck
npm run dorado -- encrypt --password-stdin --in file --out file.mahi
npm run gyotaku -- --bits 256 file
```

Cross-compatible with the Rust/Go CLIs: each can decrypt the others' `.mahi`
files (verified across KDFs, MACs, and variants).

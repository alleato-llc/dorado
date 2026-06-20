# dorado (Zig)

A Zig port of dorado (Zig 0.16), matching the Rust reference (`../rust`) and the
Go, Java, Python, C, and TypeScript ports. Same from-scratch primitives against the
same official vectors, the same on-disk container format (byte-for-byte
cross-compatible), the same CLIs, and the same streaming construction. An SDK plus
the two command-line tools.

Like the Rust reference, it **streams** over a small Reader/Writer callback
interface in constant memory (the CLIs wire it to `std.Io.File`), so inputs larger
than RAM are fine; in-memory slice wrappers are provided. Zig's native `u64` with
wrapping operators (`+%`) makes the Threefish ARX direct. Unlike the other ports,
**no external library is needed**: the KDFs come from Zig's standard library
(`std.crypto.pwhash` for Argon2id/scrypt/PBKDF2, `std.crypto.auth.hmac` for HMAC).
Educational and unaudited; for real data prefer a vetted library.

## Build

```
zig build            # builds the dorado and gyotaku executables into zig-out/bin
zig build test       # runs the test suite
```

Building against Zig 0.16 (a large breaking release): notes on the API churn and the
gotchas hit while writing this port are in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Layout

- `src/threefish.zig`, `skein.zig`, `blake3.zig` — the from-scratch primitives
  (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3), verified against the same
  vectors as the Rust reference.
- `src/format.zig`, `kdf.zig`, `mac.zig`, `engine.zig` — the construction: the
  container header, the KDFs (Zig stdlib), the MAC menu, and the streaming password
  container, raw CTR, and inspect. `engine.Error` is the error set for a bad
  container.
- `src/root.zig` — the library module root (the SDK surface).
- `src/cli_dorado.zig`, `src/cli_gyotaku.zig` — the two CLIs.
- `tests/test.zig` — the test suite (a separate module importing `dorado`), with
  cross-compat fixtures in `tests/fixtures/` embedded via `@embedFile`.

## Use

```zig
const dorado = @import("dorado");

// `init.gpa` and `init.io` come from `pub fn main(init: std.process.Init)`.
const opts = dorado.engine.Options{}; // Threefish-256, Argon2id, Skein-512
const ct = try dorado.engine.encrypt(gpa, io, password, opts, plaintext);
defer gpa.free(ct);
const pt = try dorado.engine.decrypt(gpa, io, password, null, ct);
defer gpa.free(pt);
// or stream over Reader/Writer callbacks: encryptStream / decryptStream.
```

```
zig build && ./zig-out/bin/dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
./zig-out/bin/gyotaku --bits 256 notes.txt
```

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. `tests/test.zig` decrypts fixtures produced by the Rust reference
(in `tests/fixtures/`, embedded at compile time) covering every KDF, MAC, and
variant plus a labeled and a multi-frame file; the reverse direction (the Rust CLI
decrypting Zig's output) is verified during development.

# dorado (Zig)

A Zig port of dorado (Zig 0.16), matching the Rust reference (`../rust`) and the
other ports. Same from-scratch primitives against the same official vectors, the
same on-disk container format (byte-for-byte cross-compatible), the same CLIs, and
the same streaming construction. An SDK plus the two command-line tools.

Like the Rust reference, it **streams** over a small Reader/Writer callback
interface in constant memory (the CLIs wire it to `std.Io.File`), so inputs larger
than RAM are fine; in-memory slice wrappers are provided. Zig's native `u64` with
wrapping operators (`+%`) makes the Threefish ARX direct. Unlike the other ports,
**no external library is needed**: the KDFs come from Zig's standard library
(`std.crypto.pwhash` for Argon2id/scrypt/PBKDF2, `std.crypto.auth.hmac` for HMAC).
Educational and unaudited; for real data prefer a vetted library.

## Layout

- `src/threefish.zig`, `skein.zig`, `blake3.zig` — the from-scratch primitives
  (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3), verified against the same
  vectors as the Rust reference.
- `src/format.zig`, `kdf.zig`, `mac.zig`, `engine.zig` — the construction: the
  container header, the KDFs (Zig stdlib), the MAC menu, and the streaming password
  container, raw CTR (bare and authenticated), and inspect. `engine.Error` is the error set for a bad
  container.
- `src/root.zig` — the library module root (the SDK surface).
- `src/cli_dorado.zig`, `src/cli_gyotaku.zig` — the two CLIs.
- `tests/test.zig` — the test suite (a separate module importing `dorado`), with
  cross-compat fixtures in `tests/fixtures/` embedded via `@embedFile`.

## Build

```
zig build            # builds the dorado and gyotaku executables into zig-out/bin
```

A release build defaults to `ReleaseSafe` (`zig build --release`), keeping Zig's
runtime safety checks in the shipped binary. Building against Zig 0.16 (a large
breaking release): notes on the API churn are in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Use

SDK:

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

CLI:

```
./zig-out/bin/dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
./zig-out/bin/gyotaku --bits 256 notes.txt
```

## Testing

```
zig build test           # the suite: KATs, every KDF/MAC/variant, the security
                         # properties, and the embedded Rust cross-compat fixtures
zig build freestanding   # cross-compiles the primitives to a bare-metal target
```

## Cross-compatibility

The container bytes are identical to the other ports: each can decrypt the others'
`.mahi` files. `tests/test.zig` decrypts fixtures produced by the Rust reference
(in `tests/fixtures/`, embedded at compile time) covering every KDF, MAC, and
variant plus a labeled and a multi-frame file; the reverse direction (the Rust CLI
decrypting Zig's output) is verified during development.

## Secret handling and bare-metal

The engine wipes the derived keys and the cipher's expanded key schedule with
`std.crypto.secureZero` (which the compiler cannot optimize away), on every exit path
via `defer` (the analog of Rust's `Drop`), and the `dorado` CLI holds the password in
a page-aligned, `mlock`'d buffer (the CLI links libc only for `mlock`; the SDK does
not) that is kept out of swap and wiped on free. This reduces exposure; it is not a
guarantee (the password still transits `argv`/stdin first, and `mlock` is
best-effort).

A `ReleaseSafe` default (not `ReleaseFast`) keeps Zig's runtime safety checks (bounds,
integer overflow, alignment) in the shipped binary, so a bug that could leak a secret
panics instead of becoming silent undefined behavior. Zig has no borrow checker, so
this is runtime detection of the common bug classes, not Rust's compile-time prevention.

The from-scratch primitives (Threefish/CTR, Skein, BLAKE3) need no allocator and no
OS, so `zig build freestanding` cross-compiles them (via `src/primitives.zig`) to a
bare-metal ARM object, mirroring the Rust port's `no_std` cipher crate. The
construction (its KDFs need an allocator) is not bare-metal.

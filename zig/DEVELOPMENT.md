# Zig port: development notes

Notes from building the Zig port, kept for whoever maintains or extends it. The
short version: the cryptography ported cleanly (the primitives passed their
known-answer tests almost as soon as they compiled), and essentially all of the
friction was Zig 0.16 API churn. Zig 0.16 is a large breaking release built around
the new `std.Io` interface, and most online examples target 0.13 to 0.15, so the
working reference was the standard library source itself (the `.std_dir` path from
`zig env`).

This file assumes Zig 0.16. If you bump the compiler, expect some of the items below
to move again.

## What went well (and was a little surprising)

- **No external dependency.** Alone among the ports, Zig needs nothing outside the
  standard library: `std.crypto.pwhash` ships Argon2id, scrypt, and PBKDF2, and
  `std.crypto.auth.hmac` ships HMAC-SHA256. Every other port pulls in a KDF library
  (Rust crates, Go `x/crypto`, Java Bouncy Castle, Python `argon2-cffi`, C
  `libargon2` + OpenSSL).
- **The KDFs matched the Rust reference byte-for-byte on the first try.** Zig's
  Argon2 uses version `0x13` (= 19 = `ARGON2_VERSION_13`), the same as the other
  ports, so no version-mismatch surprises. Container files cross-decrypted
  immediately once the engine compiled.
- **Native `u64` with wrapping operators (`+%`, `-%`) made the Threefish ARX
  direct.** No `BigInt` (the TypeScript port) and no `& MASK64` masking (Python,
  JavaScript). The 32-bit BLAKE3 math is the same story with `u32`.
- **The constant-time and secret-zeroing primitives already exist in std:**
  `std.crypto.timing_safe.eql` for the tag compare, and `std.crypto.secureZero` for
  wiping (relevant if you add secret-memory hygiene).

## Zig 0.16 gotchas (in roughly the order they bit)

### Allocators

- `std.heap.GeneralPurposeAllocator` is gone. The debug/leak-checking allocator is
  now `std.heap.DebugAllocator(.{}){}`. There is also `std.heap.smp_allocator` and
  `std.heap.page_allocator`.

### `std.ArrayList` is unmanaged by default

- `std.ArrayList(u8)` no longer stores its allocator. Initialize with `.empty`
  (not `.{}` or `.init(alloc)`), and pass the allocator to each method:
  `list.append(alloc, x)`, `list.appendSlice(alloc, bytes)`,
  `list.toOwnedSlice(alloc)`, `list.deinit(alloc)`. The old managed type still
  exists separately in the same file, which makes the stdlib source confusing to
  grep (two `appendSlice` signatures); the one `std.ArrayList` resolves to is the
  unmanaged one.

### Tagged unions: field names vs. method names

- A `union(Enum)` member name and a `pub fn` in the same union cannot share a name.
  We have a `Kdf` union with an `argon2id:` field, so its constructor could not be
  `pub fn argon2id(...)`; it is `pub fn mkArgon2id(...)` (likewise `mkScrypt`,
  `mkPbkdf2`). The compiler error ("duplicate union member name") points at the
  method, which is a little misleading.

### Randomness goes through `std.Io`

- `std.crypto.random` was removed, and there is no `std.posix.getrandom`.
  Cryptographic entropy comes from the `Io` interface: `io.random(buf)` (may use
  stored state) or `io.randomSecure(buf)` (always syscalls for fresh entropy,
  returns `error.EntropyUnavailable`). We use `randomSecure` for the salt and IV.

### `main` can receive `std.process.Init`

- `std.process.argsAlloc` is gone. Declare `pub fn main(init: std.process.Init) !void`
  and you get `init.io`, `init.gpa`, `init.arena`, and the command-line arguments as
  `init.minimal.args`. Iterate them with
  `std.process.Args.Iterator.init(init.minimal.args)` and `.next()`. This also hands
  you the `Io` and an allocator for free, so the CLIs do not construct their own.

### `argon2.kdf` takes an `Io`

- `std.crypto.pwhash.argon2.kdf(allocator, dk, password, salt, params, mode, io)`
  needs both an allocator and an `Io` (the `Io` drives its parallelism). Outside of
  `main`'s `Init`, build one with `var t = std.Io.Threaded.init(gpa, .{}); const io
  = t.io();` and `defer t.deinit();`. `scrypt.kdf` takes the allocator but no `io`;
  `pbkdf2` takes neither (it is `pbkdf2(dk, password, salt, rounds, Prf)` with
  `Prf = std.crypto.auth.hmac.sha2.HmacSha256`).

### File and stream I/O is reworked

- `std.fs.cwd()` is gone. Use `std.Io.Dir.cwd()`, then
  `dir.openFile(io, path, .{})` / `dir.createFile(io, path, .{})`. Standard streams
  are `std.Io.File.stdin()` / `std.Io.File.stdout()`. Close with `file.close(io)`.
- Reading and writing are buffered streaming. `file.reader(io, &buf)` returns a
  `File.Reader` whose `.interface` field is an `*std.Io.Reader`; pull bytes with
  `reader.interface.readSliceShort(dst)` (returns a short count at EOF) or
  `takeDelimiterExclusive('\n')` for a line. `file.writer(io, &buf).interface` is an
  `*std.Io.Writer`; use `writeAll`/`print` and **`flush()` before exit** or the tail
  of the output is lost. (An early "truncated output" symptom turned out to be a
  missing flush; a separate "scrambled output" symptom was just the buffered stdout
  interleaving with unbuffered shell `echo` on the same TTY, not a bug.)
- The engine deliberately does **not** use `std.Io` directly. It takes a tiny
  callback `Reader`/`Writer` (a `*anyopaque` plus a function pointer), and the CLIs
  adapt `std.Io.Reader`/`Writer` to it. That keeps the library decoupled from the
  fast-moving `std.Io` surface and makes the in-memory slice wrappers trivial.

### `@embedFile` cannot escape the module root

- Cross-compat fixtures live in `tests/fixtures/`, but `@embedFile` only reaches
  files under the importing module's root directory. Embedding them from a test file
  in `src/` failed ("embed of file outside package path"). The fix is also the
  cleaner structure: the test suite is its own module rooted at `tests/`
  (`tests/test.zig`) that imports the `dorado` library module, so the fixtures embed
  as `"fixtures/..."`. See `build.zig`.

### Testing helper rename

- `std.testing.refAllDeclsRecursive` is not available; `std.testing.refAllDecls`
  is. `root.zig`'s `test {}` uses the latter.

### Build system

- `build.zig` uses `b.addModule` for the library, `b.createModule(.{ ..., .imports =
  &.{...} })` to wire the `dorado` module into the executables and the test module,
  `b.addExecutable(.{ .root_module = ... })`, and `b.addTest(.{ .root_module = ... })`.
  The test step's root module is `tests/test.zig` (see the `@embedFile` note).
- `standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe })` makes
  `--release` build `ReleaseSafe` (safety checks kept) rather than `ReleaseFast`,
  which is the right default for a security tool. Setting `preferred_optimize_mode`
  changes the flag surface: the build offers `-Drelease=[bool]` (Debug vs the
  preferred mode) instead of a free `-Doptimize=<mode>` choice.

## Workflow that worked

Build each layer in isolation and check it against the Rust reference before moving
on. Concretely: a throwaway `zig run scratch.zig` that imported one source file,
computed a known-answer vector, and printed it next to the expected hex. The
Threefish-256 KAT, then Skein/BLAKE3, then the engine round-trip, then decrypting the
committed Rust fixtures, were each confirmed before the next was written. That caught
every 0.16 API problem at the smallest possible scope and meant the final `zig build
test` had no logic surprises left, only the API fixes already made. The Rust CLI was
the oracle throughout (it generates the fixtures and decrypts the Zig output).

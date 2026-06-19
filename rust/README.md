# dorado

## About

Dorado is a from-scratch implementation of Threefish, the tweakable block cipher at the core of the Skein hash function. It supports all three block sizes (256, 512, and 1024 bits) with both encryption and decryption, and follows the Skein 1.3 specification (including the round-3 NIST tweak to the key-schedule constant C240).

Threefish is the third cipher in Bruce Schneier's Blowfish then Twofish then Threefish line, and the cipher underneath Skein, a NIST SHA-3 finalist. It is a pure ARX design: addition, rotation by a constant, and xor, with no S-boxes or lookup tables.

The name keeps the fish theme going: a dorado is a fish, better known by its other name, the mahi-mahi. That is also where the `.mahi` extension for password-mode files comes from (see the command-line tool below).

This is an educational, unaudited implementation. For real data, prefer an audited crate. See the security note below.

## Project layout

This is a Cargo workspace of five crates:

- `crates/dorado` — the primitives library, zero runtime dependencies. Threefish + CTR is the core; alongside it are several other from-scratch primitives, each verified against official test vectors or differentially against an audited crate: Skein-512 (the hash Threefish was built for), BLAKE3, and ChaCha20 / Poly1305 / ChaCha20-Poly1305. The ChaCha primitives are library code only and are deliberately not wired into the tool, which stays Threefish-based (see "How it works").
- `crates/dorado-engine` — the shared construction (KDFs, the authenticated chunked container, raw CTR, the MAC menu). Depends on `dorado`.
- `crates/dorado-cli` — the command-line frontend (produces the `dorado` binary).
- `crates/dorado-gui` — the iced graphical frontend (produces `dorado-gui`).
- `crates/dorado-gyotaku` — a standalone Skein-512 hashing tool (produces the `gyotaku` binary), like `sha256sum` but Skein.

## Using dorado

```
cargo build --workspace      # everything
cargo test  --workspace      # all tests
cargo build -p dorado        # just the primitives library
cargo build -p dorado-gyotaku  # just the gyotaku hashing tool
cargo bench -p dorado        # cipher and hash throughput (criterion)
```

The `dorado` primitives crate is `no_std` and supports three environment levels.
With the default `alloc` feature it runs anywhere with an allocator (no OS needed),
so it builds for bare-metal targets, for example `cargo build -p dorado --target
thumbv7em-none-eabi`. With `--no-default-features` it is fully allocation-free, with
the heap not even linked: Threefish, CTR, ChaCha20, Poly1305, the incremental
hashers (`Skein512`, `blake3::Hasher`) and their `*_into` one-shots, and the
in-place ChaCha20-Poly1305 AEAD. The hashers stream, so an input larger than memory
can be hashed (the `gyotaku` CLI reads files in fixed buffers). Only the
`Vec`-returning convenience wrappers require `alloc`. The default `zeroize` feature
wipes each cipher's key schedule on drop. For RustCrypto interop, the optional
`cipher` feature implements the block-cipher traits for the Threefish variants
(generic modes, AEADs), and the optional `digest` feature implements the hash
traits (BLAKE3 as a 32-byte `Digest`, and `Skein512_256` / `Skein512_512`).

### Library

One type per block size: `Threefish256`, `Threefish512`, `Threefish1024`. Each is built from a key and a 16-byte tweak and works on a fixed-size block in place. Keys, tweaks, and blocks are little-endian. Key and block sizes are 32, 64, and 128 bytes respectively.

```rust
use dorado::Threefish256;

let cipher = Threefish256::new(&[0u8; 32], &[0u8; 16]); // key, tweak

let mut block = [0u8; 32];
cipher.encrypt_block(&mut block);
cipher.decrypt_block(&mut block); // back to the original

// CTR mode handles any length; the same call decrypts.
let iv = [0u8; 32];
let mut data = b"any length, not just one block".to_vec();
cipher.ctr_apply(&iv, &mut data);
cipher.ctr_apply(&iv, &mut data);
```

### Command-line tool

The tool runs over stdin/stdout or files, streaming in constant memory. It takes the key two ways.

Build it once:

```
cargo build --release -p dorado-cli
```

That produces the binary at `target/release/dorado`, which the examples below call directly. To put `dorado` on your PATH, run `cargo install --path crates/dorado-cli`. During development you can skip the build step and substitute `cargo run -p dorado-cli --` for the binary path, which compiles and runs in one go (for example `cargo run -p dorado-cli -- encrypt --password --in plain --out cipher`).

With a raw key you supply the key bytes (hex) and the IV. Output is bare, unauthenticated CTR ciphertext. The key length selects the variant. Use `--key-file <path>` to keep the key off the process list.

```
target/release/dorado encrypt --key <hex> --iv <hex> --in plain --out cipher
target/release/dorado decrypt --key <hex> --iv <hex> --in cipher --out plain
```

With a password the tool derives the key with a KDF and writes an authenticated, self-describing file. Decryption only needs the password, and reports a wrong password or a tampered or truncated file as an error. These files use the `.mahi`
extension by convention (a nod to dorado's namesake, the mahi-mahi fish); the tool reads them by content, not by name, so the extension is not required.

```
target/release/dorado encrypt --password --in notes.txt --out notes.txt.mahi
target/release/dorado decrypt --password --in notes.txt.mahi --out notes.txt
```

`--password-stdin` reads the password from stdin for scripting (data must then come from `--in`). The KDF defaults to Argon2id (`--kdf argon2id|scrypt|pbkdf2`), the variant to 256 (`--variant`), and the chunk size to 64 KiB (`--chunk-kib`). The authentication MAC defaults to Skein-512 (`--mac skein|hmac-sha256|blake3`); all three are from-scratch, produce 32-byte tags, and are authenticated by the header so the choice cannot be altered undetected. Run with `--help` for the full list of KDF cost flags. Defaults should be tuned and measured on your own hardware.

An optional `--label` binds a non-secret string (a filename, a purpose) into the file. It is authenticated and shown by `inspect`, and on decryption `--expect-label` requires it to match, rejecting a substituted-but-otherwise-valid file before any output is written:

```
target/release/dorado encrypt --password --label "backup-2026" --in notes.txt --out notes.txt.mahi
target/release/dorado decrypt --password --expect-label "backup-2026" --in notes.txt.mahi --out notes.txt
```

`dorado inspect` reports a password file's non-secret parameters (format version, variant, KDF and its costs, MAC, chunk size, salt length, tweak, label) without a password and without decrypting, reading only the header:

```
target/release/dorado inspect --in notes.txt.mahi
```

### gyotaku: the Skein hashing tool

`crates/dorado-gyotaku` builds a standalone `gyotaku` binary: a Skein-512 hash like `sha256sum`, but Skein. The name is the Japanese art of printing a fish in ink, a fingerprint of the fish, which is what this makes of a file. It is Skein in its primary, unkeyed role (fingerprinting files or streams), as opposed to the keyed MAC the encryption tool uses internally, and it reuses the same verified `dorado::skein` primitive.

```
cargo build --release -p dorado-gyotaku
target/release/gyotaku file.txt              # 256-bit digest, "digest  file.txt"
target/release/gyotaku --bits 512 file.txt   # any whole-byte length Skein supports
echo -n abc | target/release/gyotaku         # reads stdin when no files are given
target/release/gyotaku --tag file.txt        # BSD-style "SKEIN-512 (file.txt) = ..."
target/release/gyotaku file.txt > sums       # then verify, like sha256sum -c:
target/release/gyotaku -c sums               # prints "file.txt: OK", fails on mismatch
```

### GUI demo

The `dorado-gui` crate is a small graphical demo built on [iced](https://iced.rs/). It is the password tool in a window: pick a source (typed text or a file) and a direction (encrypt or decrypt), enter a password, and run. A collapsible Options panel exposes the variant, KDF and its cost parameters, chunk size, and an optional tweak. The key derivation runs on a background thread so the window stays responsive; build with `--release` for snappy performance, since the KDF is deliberately slow and a debug build makes it much slower.

```
cargo run --release -p dorado-gui
```

The GUI is a separate binary that shares the same construction as the CLI, so it is for the same educational purpose and carries the same caveats. iced pulls in a large graphics stack, which is why it is its own crate.

## How it works

Dorado is built in layers, each wrapped around the one below:

- **Threefish is the algorithm**: the block cipher itself, which transforms one   fixed-size block. This is what the library implements and what the test vectors   check.
- **CTR is a mode**: a generic recipe that wraps the cipher to handle any length. It only calls the cipher and contains no cipher internals.
- **The frontends add the rest**: key derivation from a password, encrypt-then-MAC authentication, and a streaming chunked file format, all standard constructions on top of CTR. This shared construction lives in one place and is used by both the CLI and the GUI demo. The MAC is a choice of three from-scratch keyed hashes (Skein-512 by default, HMAC-SHA256, or BLAKE3 keyed); all are pseudorandom-function MACs that drop into the same encrypt-then-MAC slot.

Skein, the hash function Threefish was designed to power, is another construction on Threefish, a sibling of CTR. It is built from scratch in `crates/dorado` and surfaced two ways: as the default authentication MAC above, and as the standalone `gyotaku` hashing tool. ChaCha20-Poly1305 is also implemented from scratch as library code, but it is an integrated cipher-plus-MAC, so wiring it in would replace Threefish rather than extend it; dorado stays a Threefish project, so it is left as a verified primitive only and is not part of the tool. See the documentation below for the full picture, threat model, and wire format.

## Security note

This is an educational, unaudited implementation with no broader key management. The library API exposes only the unauthenticated cipher and CTR. In the CLI,password files are authenticated (encrypt-then-MAC), so tampering, a wrong password, reordered or dropped chunks, and truncation are detected; raw-key mode is bare CTR with no integrity, by design. The CLI wipes passwords and derived keys from memory when they go out of scope.

Dorado is not described as secure, production-ready, or guaranteed constant-time. The ARX design uses only data-independent operations (no secret-dependent table lookups or branches), so a straightforward build behaves in constant time on typical hardware, but that is a property of the design, not a promise. The full threat model, including what is not defended, is in `docs/overview.md`.

## Documentation

The `docs/` directory has three documents, by depth:

- `docs/overview.md`: the conceptual tour for a general technologist, with diagrams of the layers and the encrypt and decrypt flows, and the threat model.
- `docs/spec.md`: the precise, byte-level wire format and cipher constants, the single source of truth for the on-disk container.
- `docs/glossary.md`: definitions of the concepts used here (block cipher, CTR, KDF, MAC, AEAD, and more) for a technical reader who is not a cryptographer.

## License

Licensed under the MIT License (SPDX `MIT`). See `../LICENSE`.

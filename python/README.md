# dorado (Python)

A Python port of dorado, matching the Rust reference (`../rust`) and the other
ports. Same from-scratch primitives against the same official vectors, the same
on-disk container format (byte-for-byte cross-compatible), the same CLIs, and the
same streaming construction. An SDK plus the two command-line tools.

Like the Rust reference, it **streams** over binary file-like objects in constant
memory, so inputs larger than RAM are fine; in-memory `bytes` wrappers are provided.
Python ints are arbitrary precision, so the 64-bit ARX is done modulo 2**64 with an
explicit mask. Educational and unaudited; for real data prefer a vetted library.

## Layout

- `src/dorado/threefish.py`, `skein.py`, `blake3.py` — the from-scratch primitives
  (Threefish 256/512/1024 + CTR, Skein-512, BLAKE3), verified against the same
  vectors as the Rust reference.
- `src/dorado/format.py`, `kdf.py`, `mac.py`, `engine.py` — the construction: the
  container header, both forms of key derivation (`derive_from_password`, the slow
  password KDFs: Argon2id via `argon2-cffi`, scrypt and PBKDF2 from `hashlib`; and
  `derive_from_key`/`derive_from_key_with`, the fast key-based fan-out over the
  from-scratch Skein-512 or BLAKE3 keyed hash, selected by `KdfPrf`), the MAC menu
  (HMAC-SHA256 from `hmac`), and the streaming password container, raw CTR (bare
  and authenticated), and inspect. `DoradoError` marks a bad container.
- `src/dorado/cli/dorado.py`, `cli/gyotaku.py` — the two CLIs.

The cipher and hashes are from-scratch; only Argon2id is a dependency
(`argon2-cffi`), matching the other ports' use of a KDF library.

## Build

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Use

SDK:

```python
from dorado import encrypt_password, decrypt_password, default_options

container = encrypt_password(b"correct horse", default_options(), plaintext)
recovered = decrypt_password(b"correct horse", container)
# or stream in constant memory:
#   encrypt_password_stream(password, opts, reader, writer)
#   decrypt_password_stream(password, reader, writer)
```

Fan a strong key out into per-purpose subkeys (fast, no stretching; never pass a
password here, that is `derive_from_password`'s job):

```python
from dorado import derive_from_key

index_key = derive_from_key(master, "myapp/index", 32)
data_key = derive_from_key(master, "myapp/data", 32)
```

CLI:

```
dorado encrypt --password-stdin --in notes.txt --out notes.txt.mahi
gyotaku --bits 256 notes.txt
```

Raw-key mode (`--key`/`--key-file` + `--iv`) is authenticated by default
(encrypt-then-MAC, per `--mac` and `--chunk-kib`); add `--unauthenticated` to
opt into bare CTR (output length equals input length, no tamper detection).
Password mode is always authenticated.

## Testing

```
pytest        # KATs, every KDF/MAC/variant, the security properties, and
              # cross-compat fixtures made by the Rust CLI
```

## Cross-compatibility

The container bytes are identical to the Rust/Go/Java/TypeScript/C/Zig ports: each
can decrypt the others' `.mahi` files. `tests/test_crosscompat.py` decrypts fixtures
produced by the Rust reference (in `tests/fixtures/`) covering every KDF, MAC, and
variant plus a labeled and a multi-frame file; the reverse direction is verified
during development.

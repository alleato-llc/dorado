# Dorado wire format and constants

This is the precise, byte-level reference for dorado's CLI container format and the
cipher constants it relies on. It is the single source of truth for the on-disk
format; the conceptual tour lives in `overview.md` and term definitions in
`glossary.md`.

All multi-byte integers in the container are big-endian, and every field is
byte-aligned (there is no bit packing). The current container format is version 4;
version 3 (identical but without the optional label field) is still read.

## Cipher constants

Threefish is implemented for three sizes. The variant also fixes the key length,
the block length, and the IV length (all equal).

| Variant | Code | Block / key / IV bytes | State words (Nw) | Rounds |
| --- | --- | --- | --- | --- |
| Threefish256 | 0 | 32 | 4 | 72 |
| Threefish512 | 1 | 64 | 8 | 72 |
| Threefish1024 | 2 | 128 | 16 | 80 |

- Key-schedule constant: `C240 = 0x1BD11BDAA9FC1A22` (the Skein 1.3 round-3 value).
- A subkey is injected every fourth round and once more at the end.
- The extended key is the `Nw` key words plus a parity word (`C240` XORed with all
  key words). The extended tweak is `t0, t1, t0 ^ t1`.
- All cipher word arithmetic wraps modulo 2 to the 64th.
- Bytes convert to and from `u64` words little-endian at the API boundary.

These values are verified against official test vectors and must not be changed
without re-running the full suite.

## File extension

Password-mode output uses the extension **`.mahi`** by convention, a nod to
dorado's namesake (the dorado fish is also called mahi-mahi), for example
`notes.txt.mahi`. The extension is only a human convention and is separate from the
on-disk format: the tool identifies a file by its magic bytes (`DRDO`), not its
name, and does not require or add the extension. Raw-key mode produces bare,
headerless ciphertext with no self-describing format, so no extension is implied
for it.

## Container layout

A password file is a header followed by a sequence of frames.

```
Header
  magic            "DRDO"                       4 bytes
  version          4 (3 still read)             1 byte
  variant          0 = 256, 1 = 512, 2 = 1024   1 byte
  kdf id           1 = argon2id, 2 = scrypt,    1 byte
                   3 = pbkdf2
  kdf params       per kdf id (see below)       variable
  mac id           1 = HMAC-SHA256,            1 byte
                   2 = Skein-512, 3 = BLAKE3
  chunk size       plaintext bytes per chunk    4 bytes (u32)
  salt len         length of salt in bytes      1 byte
  salt             salt                         salt_len bytes (16 in practice)
  tweak            tweak                        16 bytes
  iv               initial counter              block-size bytes (32 / 64 / 128)
  label len        length of label (v4+ only)   2 bytes (u16)
  label            optional label (v4+ only)    label_len bytes (0 to 4096)

Frames (one or more, repeated until is_last = 1)
  is_last          0 or 1                       1 byte
  ct_len           ciphertext length            4 bytes (u32)
  ciphertext       this chunk's ciphertext      ct_len bytes
  tag              MAC over the AAD (see below)  32 bytes
```

The `label len` and `label` fields exist only in version 4 and later, appended
after the IV so the version-3 prefix is byte-identical. A version-3 file has no
label fields; it is still accepted on read, and `label` is treated as empty.

Everything in the header is non-secret. The header is parsed with a streaming
reader, so decryption never buffers the whole file.

### KDF parameter encodings

The bytes following the `kdf id` depend on which KDF it names:

```
argon2id (id 1)   m_cost  u32   memory in KiB
                  t_cost  u32   iterations
                  p_cost  u32   lanes                       (12 bytes total)

scrypt   (id 2)   log_n   u8    log2 of the cost parameter N
                  r       u32   block-size factor
                  p       u32   parallelization factor      (9 bytes total)

pbkdf2   (id 3)   rounds  u32   iteration count
                  prf id  u8    1 = HMAC-SHA256              (5 bytes total)
```

### MAC

The `mac id` selects the MAC: `1` HMAC-SHA256, `2` Skein-512 (the default; a
Threefish-native keyed hash), or `3` BLAKE3 keyed. All three take the 32-byte MAC
key and produce a 32-byte tag, so the frame layout is identical regardless of
choice. The id is authenticated (the header is bound into chunk 0's tag), so it
cannot be altered undetected.

### Label (version 4+)

The optional label is a non-secret, caller-supplied byte string (a filename, a
purpose, a context) up to 4096 bytes. It is stored in the clear and, like the rest
of the header, authenticated by being bound into chunk 0's tag, so it is
tamper-evident but readable (the `inspect` command shows it). Its purpose is to
bind a file to a context: decryption can require an expected label, and a file
whose label differs (or which carries no label) is rejected before any plaintext
is written. Because the label is authenticated, an attacker cannot present a
substituted-but-valid file under a forged label. Supplying no expected label
decrypts regardless of the stored label.

## Keys and the counter

The KDF is asked for `key_len + 32` bytes and the result is split: the first
`key_len` bytes are the encryption key, the last 32 are the MAC key.

The keystream is one continuous CTR stream across all chunks. Encryption starts the
counter at the header IV and increments it per block. After each full (non-final)
chunk, the counter advances by `chunk_size / block_size` blocks, so chunk `i` picks
up exactly where chunk `i - 1` left off. The ciphertext bytes are therefore
identical to whole-file CTR; only the framing and tags are added.

The counter is the IV interpreted as a big-endian integer, incremented with
wraparound. It is public, so no constant-time handling is needed.

## Frame authentication (AAD)

Each frame's tag is `MAC(mac_key, AAD)` under the selected MAC, where the
authenticated data is built as follows:

```
AAD = "DRDOchnk"                          domain separator, 8 bytes
      || header bytes                     only for chunk index 0
      || index            u64, big-endian
      || is_last          1 byte
      || ct_len           u32, big-endian
      || ciphertext
```

The roles of the fields:

- The **domain separator** keeps these tags from being confused with any other use
  of the MAC key.
- The **header bytes**, bound into the first frame only, authenticate every
  parameter (variant, KDF id and settings, salt, tweak, IV, and the label). The stored tag was
  computed over the original header; reserializing a tampered header yields
  different bytes and the tag fails.
- The **index** defeats reordering and duplication of frames.
- The **is_last flag**, combined with the rule that decryption must see an
  authenticated last frame before end of input, defeats truncation.
- The **ct_len** and **ciphertext** authenticate the chunk's contents and length.

Decryption recomputes the AAD from the bytes it reads and verifies the tag before
decrypting the chunk. Verification failure means a wrong password, a corrupted
file, or tampering, and decryption stops.

## Bounds and validation

- `chunk_size` must be non-zero, at most 2^30 bytes, and a multiple of the variant's
  block size. The CLI default is 64 KiB.
- A frame's `ct_len` must not exceed the header `chunk_size`; this bounds per-frame
  allocation before any data is read.
- Every non-final frame must carry exactly `chunk_size` plaintext bytes, which keeps
  the continuous counter in step.
- Reaching end of input without an `is_last = 1` frame is a truncation error.

## Versioning

The format is identified by the magic `DRDO` and a one-byte version. Decryption
rejects an unknown magic or an unsupported version with a clear error. Any change to
the layout is a version bump (`format::VERSION`, currently 4). A header read from a
file keeps its own version so it reserializes byte-for-byte (its tag still
verifies); the reader currently accepts versions 3 and 4, and writes 4.

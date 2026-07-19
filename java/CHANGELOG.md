# Changelog - Java port

Changes to the **Java port only** (`java/`). Cross-cutting changes (project docs, the
chunk-size cap policy, the wire format) live in the [Core CHANGELOG](../CHANGELOG.md) and
[docs/spec.md](../docs/spec.md); this file records the Java-specific details. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). [VERSIONS.md](../VERSIONS.md) is
the master table.

## [Unreleased]

### Added

- **Raw-key mode gains an authenticated option**: `Engine.{encrypt,decrypt}RawAuthenticatedStream`
  / `{encrypt,decrypt}RawAuthenticated`, encrypt-then-MAC over a caller-supplied key
  with no password or KDF, reusing the password container's chunk/frame machinery
  and `AuthenticationException` for a failed tag. See the
  [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale and
  [docs/spec.md](../docs/spec.md)'s "Raw-key modes" section for the byte-level
  construction (key-splitting via domain-separated Skein-512, the frame AAD).
  Bare `rawCtrStream`/`rawCtr` are unchanged and remain the default. Verified against
  the shared cross-language known-answer vectors in
  `docs/fixtures/raw-authenticated.md`.
- Typed exceptions `AuthenticationException` and `MalformedContainerException` under
  `DoradoException`, so container failures are type-distinguishable. Wrong password and
  tampering stay merged as `AuthenticationException` (same type and message). Encrypt-side
  parameter checks remain `IllegalArgumentException`.
- A fuzz/property test feeding random, truncated, and mutated bytes to the decrypt path,
  asserting only exceptions (never a crash) and never an over-allocation.
- **Key-based derivation**: `Kdf.deriveFromKey(key, domain, outLen)`, the fast form of
  key derivation (one domain-separated Skein-512 keyed hash under the `DRDOkdrv`
  prefix, no salt, no cost parameters), fanning an already high-entropy key out into
  independent per-purpose children, plus `Kdf.deriveFromKeyWith(prf, ...)` with a
  `Kdf.KdfPrf` enum (`SKEIN512`, the default; `BLAKE3`, requiring a 32-byte key) to
  fan out under a caller-chosen PRF. Uses this port's from-scratch Skein-512 and
  BLAKE3, not Bouncy Castle. Library API only; the container wire format is
  unchanged. See the [Core CHANGELOG](../CHANGELOG.md) for the cross-port rationale;
  verified against the shared cross-language known-answer vectors in
  `docs/fixtures/derive-from-key.md`.

### Fixed

- `Kdf.validate` now rejects `rounds == 0` for PBKDF2 ("pbkdf2 rounds must be
  nonzero", a `MalformedContainerException` like the other bounds). Zero rounds would
  "derive" an all-zero key without error; a crafted or corrupted header carrying it
  now fails cleanly at validation instead. Matches the Rust reference.

### Changed

- `Kdf.derive` is renamed to `Kdf.deriveFromPassword`, paralleling the new
  `Kdf.deriveFromKey` the way the Rust reference renamed its `derive`. The parallel
  names are the guardrail: a password must never take the fast path, a key never
  needs the slow one.
- Best-effort zeroization of derived key material (`Arrays.fill` in a `finally`), with an
  honest note that the JVM may have copied or relocated the array.
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (MAC verify already used
  `MessageDigest.isEqual` and the RNG already `SecureRandom`, so no change there.)

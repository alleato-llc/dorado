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

### Changed

- Best-effort zeroization of derived key material (`Arrays.fill` in a `finally`), with an
  honest note that the JVM may have copied or relocated the array.
- Applied the chunk-size cap policy (64 MiB default, 1 GiB hard ceiling,
  `DORADO_MAX_CHUNK_BYTES`); see [Core](../CHANGELOG.md). (MAC verify already used
  `MessageDigest.isEqual` and the RNG already `SecureRandom`, so no change there.)

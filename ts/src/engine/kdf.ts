// Key derivation, in its two standard forms.
//
// deriveFromPassword is password-based derivation (a PBKDF), via hash-wasm
// (WASM Argon2id/scrypt/PBKDF2, isomorphic across Node and the browser; these
// are standard algorithms, so the outputs match the Rust/Go ports): it
// stretches a weak, guessable secret into a raw key, deliberately slowly,
// under caller-tunable cost parameters (validate bounds untrusted ones).
//
// deriveFromKey is key-based derivation (a KBKDF): it splits an already
// high-entropy key into independent, domain-separated children, fast (one
// keyed hash over the port's own from-scratch primitives, via the swappable
// cipher backend), with no salt and no cost parameters because there is
// nothing to stretch. The keyed hash defaults to Skein-512 (Threefish's
// native companion); deriveFromKeyWith lets a caller pick the PRF (KdfPrf)
// instead, e.g. BLAKE3 to keep a ChaCha-family construction single-family top
// to bottom. Every secure PRF does this job identically, so the choice is
// about matching the surrounding cipher, not security. The names are the
// guardrail: a password must never take the fast path, and a key never needs
// the slow one.

import { argon2id, scrypt, pbkdf2, createSHA256 } from "hash-wasm";
import { type KDFParams, KDF_ARGON2ID, KDF_SCRYPT, KDF_PBKDF2 } from "./format";
import { InvalidParamsError } from "./errors";
import { type CipherBackend, tsBackend } from "./backend";
import { concat, utf8 } from "../bytes";

/**
 * Derive `outLen` key bytes from `password` and `salt` using `p` — password-
 * based derivation, deliberately slow (the cost is what an attacker pays per
 * guess). For deriving from an already-strong key, use {@link deriveFromKey}
 * instead.
 */
export async function deriveFromPassword(p: KDFParams, password: Uint8Array, salt: Uint8Array, outLen: number): Promise<Uint8Array> {
  switch (p.kind) {
    case KDF_ARGON2ID:
      return (await argon2id({
        password,
        salt,
        parallelism: p.pCost!,
        iterations: p.tCost!,
        memorySize: p.mCost!, // KiB
        hashLength: outLen,
        outputType: "binary",
      })) as Uint8Array;
    case KDF_SCRYPT:
      return (await scrypt({
        password,
        salt,
        costFactor: 1 << p.logN!,
        blockSize: p.r!,
        parallelism: p.p!,
        hashLength: outLen,
        outputType: "binary",
      })) as Uint8Array;
    case KDF_PBKDF2:
      return (await pbkdf2({
        password,
        salt,
        iterations: p.rounds!,
        hashLength: outLen,
        hashFunction: createSHA256(),
        outputType: "binary",
      })) as Uint8Array;
  }
  throw new InvalidParamsError(`unknown kdf kind ${p.kind}`);
}

/**
 * The keyed hash {@link deriveFromKeyWith} fans a master key out with. Both
 * are secure PRFs and produce identically strong children; the choice exists
 * only to let a construction stay within one cryptographic family (Skein for
 * Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
 * "skein512" (the default, and what {@link deriveFromKey} uses) accepts a key
 * of any length; "blake3" requires a 32-byte key (BLAKE3's keyed mode is
 * defined only for a 256-bit key) and throws on other lengths.
 */
export type KdfPrf = "skein512" | "blake3";

// Fixed prefix domain-separating deriveFromKey's keyed hashing from every
// other keyed use in the engine (DRDOrawE/DRDOrawM in the raw-key split,
// DRDOchnk/DRDOrwFr in the frame MACs).
const DERIVE_FROM_KEY_DOMAIN = "DRDOkdrv";

/**
 * Derive `outLen` key bytes from an already high-entropy `key`, separated by
 * `domain` — key-based derivation (the fast form): one domain-separated
 * Skein-512 keyed hash, no salt, no cost parameters, because a strong key has
 * nothing to stretch. Deterministic: the same key and domain always yield the
 * same bytes, and different domains yield computationally unrelated ones, so
 * a caller can fan one master key out into independent per-purpose keys
 * (`deriveFromKey(master, "myapp/index", 32)`,
 * `deriveFromKey(master, "myapp/data", 32)`). Never pass a password here:
 * there is no stretching, so a guessable input stays guessable — that is
 * {@link deriveFromPassword}'s job. To fan out with a different PRF (e.g.
 * BLAKE3), use {@link deriveFromKeyWith}.
 */
export function deriveFromKey(key: Uint8Array, domain: string, outLen: number, backend: CipherBackend = tsBackend): Uint8Array {
  return deriveFromKeyWith("skein512", key, domain, outLen, backend);
}

/**
 * {@link deriveFromKey} with a caller-chosen PRF ({@link KdfPrf}). The domain
 * separation, determinism, and "never pass a password" contract are exactly
 * the same; only the underlying keyed hash changes. With "skein512" this is
 * byte-for-byte identical to {@link deriveFromKey}. "blake3" requires `key`
 * to be 32 bytes and throws {@link InvalidParamsError} otherwise.
 */
export function deriveFromKeyWith(
  prf: KdfPrf,
  key: Uint8Array,
  domain: string,
  outLen: number,
  backend: CipherBackend = tsBackend,
): Uint8Array {
  const msg = concat(utf8(DERIVE_FROM_KEY_DOMAIN), utf8(domain));
  switch (prf) {
    case "skein512":
      return backend.skeinMac(key, outLen, msg);
    case "blake3":
      if (key.length !== 32) {
        throw new InvalidParamsError(`deriveFromKeyWith(blake3) requires a 32-byte key, got ${key.length}`);
      }
      return backend.blake3KeyedMac(key, outLen, msg);
  }
}

/** Reject KDF parameters whose cost is unreasonably large (untrusted header). */
export function validate(p: KDFParams): void {
  if (p.kind === KDF_ARGON2ID) {
    if (p.mCost! > 1 << 21) throw new InvalidParamsError("argon2 memory cost too large");
    if (p.tCost! > 64) throw new InvalidParamsError("argon2 time cost too large");
    if (p.pCost! > 16) throw new InvalidParamsError("argon2 parallelism too large");
  } else if (p.kind === KDF_SCRYPT) {
    if (p.logN! > 21) throw new InvalidParamsError("scrypt cost (log2 N) too large");
    if (p.r! > 32) throw new InvalidParamsError("scrypt block factor r too large");
    if (p.p! > 16) throw new InvalidParamsError("scrypt parallelism p too large");
  } else if (p.kind === KDF_PBKDF2) {
    // Zero rounds would "derive" an all-zero key without error.
    if (p.rounds! === 0) throw new InvalidParamsError("pbkdf2 rounds must be nonzero");
    if (p.rounds! > 50_000_000) throw new InvalidParamsError("pbkdf2 rounds too large");
  }
}

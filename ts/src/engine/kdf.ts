// Key derivation via hash-wasm (WASM Argon2id/scrypt/PBKDF2), isomorphic across
// Node and the browser. These are standard algorithms, so the outputs match the
// Rust/Go ports.

import { argon2id, scrypt, pbkdf2, createSHA256 } from "hash-wasm";
import { type KDFParams, KDF_ARGON2ID, KDF_SCRYPT, KDF_PBKDF2 } from "./format";

export async function derive(p: KDFParams, password: Uint8Array, salt: Uint8Array, outLen: number): Promise<Uint8Array> {
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
  throw new Error(`unknown kdf kind ${p.kind}`);
}

/** Reject KDF parameters whose cost is unreasonably large (untrusted header). */
export function validate(p: KDFParams): void {
  if (p.kind === KDF_ARGON2ID) {
    if (p.mCost! > 1 << 21) throw new Error("argon2 memory cost too large");
    if (p.tCost! > 64) throw new Error("argon2 time cost too large");
    if (p.pCost! > 16) throw new Error("argon2 parallelism too large");
  } else if (p.kind === KDF_SCRYPT) {
    if (p.logN! > 21) throw new Error("scrypt cost (log2 N) too large");
    if (p.r! > 32) throw new Error("scrypt block factor r too large");
    if (p.p! > 16) throw new Error("scrypt parallelism p too large");
  } else if (p.kind === KDF_PBKDF2) {
    if (p.rounds! > 50_000_000) throw new Error("pbkdf2 rounds too large");
  }
}

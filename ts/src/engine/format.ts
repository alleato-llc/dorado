// Wire format for the dorado password container, matching the Rust/Go ports
// byte-for-byte (version 4; version 3 still read). All multi-byte integers are
// big-endian.

import { concat } from "../bytes";
import { MalformedContainerError } from "./errors";

export const MAGIC = "DRDO";
export const FORMAT_VERSION = 4;
export const DEFAULT_CHUNK_BYTES = 64 * 1024;
// Hard ceiling on the accepted chunk size. A header may never declare a chunk
// larger than this, and the env override can only tighten the cap below it.
export const MAX_CHUNK_BYTES = 1 << 30; // 1 GiB
// Default accepted cap, applied when DORADO_MAX_CHUNK_BYTES is unset or invalid.
export const DEFAULT_MAX_CHUNK_BYTES = 64 * 1024 * 1024; // 64 MiB
export const MAX_LABEL_LEN = 4096;
export const MAC_KEY_LEN = 32;
export const TAG_LEN = 32;

export const T256 = 0;
export const T512 = 1;
export const T1024 = 2;
export type Variant = 0 | 1 | 2;

// Resolve the effective accepted chunk-size cap from a raw override string (the
// value of DORADO_MAX_CHUNK_BYTES). Pure: no IO, so it is directly testable.
// An unset, empty, or unparseable value yields the default cap. A valid value is
// clamped into [1, MAX_CHUNK_BYTES], so the override can only tighten the cap
// below the hard ceiling, never raise it.
export function chunkCapFrom(override: string | undefined): number {
  if (override === undefined) return DEFAULT_MAX_CHUNK_BYTES;
  const trimmed = override.trim();
  if (trimmed === "") return DEFAULT_MAX_CHUNK_BYTES;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) return DEFAULT_MAX_CHUNK_BYTES;
  if (n < 1) return 1;
  if (n > MAX_CHUNK_BYTES) return MAX_CHUNK_BYTES;
  return n;
}

// Browser-safe wrapper: reads DORADO_MAX_CHUNK_BYTES when a process.env exists
// (Node) and otherwise falls back to the default cap (the browser has no process).
export function effectiveMaxChunkBytes(): number {
  const override =
    typeof process !== "undefined" && process.env ? process.env.DORADO_MAX_CHUNK_BYTES : undefined;
  return chunkCapFrom(override);
}

export function keyLen(v: Variant): number {
  return v === T256 ? 32 : v === T512 ? 64 : 128;
}
export function blockLen(v: Variant): number {
  return keyLen(v);
}

export const MAC_HMAC = 1;
export const MAC_SKEIN = 2;
export const MAC_BLAKE3 = 3;
export type MacId = 1 | 2 | 3;

export const KDF_ARGON2ID = 1;
export const KDF_SCRYPT = 2;
export const KDF_PBKDF2 = 3;

export interface KDFParams {
  kind: number;
  mCost?: number;
  tCost?: number;
  pCost?: number;
  logN?: number;
  r?: number;
  p?: number;
  rounds?: number;
}

export interface Header {
  version: number;
  variant: Variant;
  kdf: KDFParams;
  mac: MacId;
  chunkSize: number;
  salt: Uint8Array;
  tweak: Uint8Array; // 16 bytes
  iv: Uint8Array;
  label: Uint8Array;
}

function u16be(v: number): Uint8Array {
  return new Uint8Array([(v >> 8) & 0xff, v & 0xff]);
}
function u32be(v: number): Uint8Array {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

export function marshalHeader(h: Header): Uint8Array {
  const parts: Uint8Array[] = [new TextEncoder().encode(MAGIC), new Uint8Array([h.version, h.variant])];
  switch (h.kdf.kind) {
    case KDF_ARGON2ID:
      parts.push(new Uint8Array([1]), u32be(h.kdf.mCost!), u32be(h.kdf.tCost!), u32be(h.kdf.pCost!));
      break;
    case KDF_SCRYPT:
      parts.push(new Uint8Array([2, h.kdf.logN!]), u32be(h.kdf.r!), u32be(h.kdf.p!));
      break;
    case KDF_PBKDF2:
      parts.push(new Uint8Array([3]), u32be(h.kdf.rounds!), new Uint8Array([1]));
      break;
  }
  parts.push(new Uint8Array([h.mac]), u32be(h.chunkSize), new Uint8Array([h.salt.length]), h.salt, h.tweak, h.iv);
  if (h.version >= 4) parts.push(u16be(h.label.length), h.label);
  return concat(...parts);
}

class Cursor {
  pos = 0;
  constructor(private readonly data: Uint8Array) {}
  read(n: number, what: string): Uint8Array {
    if (this.pos + n > this.data.length) throw new MalformedContainerError(`header truncated reading ${what}`);
    const s = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return s;
  }
  byte(what: string): number {
    return this.read(1, what)[0];
  }
  u16(what: string): number {
    const b = this.read(2, what);
    return (b[0] << 8) | b[1];
  }
  u32(what: string): number {
    const b = this.read(4, what);
    return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  }
}

/** Parse a header, returning it and the offset at which frames begin. */
export function readHeader(data: Uint8Array): { header: Header; offset: number } {
  const c = new Cursor(data);
  if (new TextDecoder().decode(c.read(4, "magic")) !== MAGIC) {
    throw new MalformedContainerError("not a dorado password file (bad magic)");
  }
  const version = c.byte("version");
  if (version !== 3 && version !== FORMAT_VERSION) throw new MalformedContainerError(`unsupported format version ${version}`);
  const variant = c.byte("variant");
  if (variant > 2) throw new MalformedContainerError(`unknown variant code ${variant}`);

  const kdfId = c.byte("kdf id");
  const kdf: KDFParams = { kind: kdfId };
  if (kdfId === KDF_ARGON2ID) {
    kdf.mCost = c.u32("m_cost");
    kdf.tCost = c.u32("t_cost");
    kdf.pCost = c.u32("p_cost");
  } else if (kdfId === KDF_SCRYPT) {
    kdf.logN = c.byte("log_n");
    kdf.r = c.u32("r");
    kdf.p = c.u32("p");
  } else if (kdfId === KDF_PBKDF2) {
    kdf.rounds = c.u32("rounds");
    if (c.byte("prf") !== 1) throw new MalformedContainerError("unknown prf id");
  } else {
    throw new MalformedContainerError(`unknown kdf id ${kdfId}`);
  }

  const mac = c.byte("mac id");
  if (mac < 1 || mac > 3) throw new MalformedContainerError(`unknown mac id ${mac}`);
  const chunkSize = c.u32("chunk size");
  const saltLen = c.byte("salt len");
  const salt = c.read(saltLen, "salt").slice();
  const tweak = c.read(16, "tweak").slice();
  const iv = c.read(blockLen(variant as Variant), "iv").slice();
  let label = new Uint8Array(0);
  if (version >= 4) {
    const labelLen = c.u16("label len");
    if (labelLen > MAX_LABEL_LEN) throw new MalformedContainerError(`label too long (${labelLen} bytes)`);
    label = c.read(labelLen, "label").slice();
  }

  return {
    header: { version, variant: variant as Variant, kdf, mac: mac as MacId, chunkSize, salt, tweak, iv, label },
    offset: c.pos,
  };
}

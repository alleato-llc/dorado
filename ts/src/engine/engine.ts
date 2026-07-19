// The authenticated chunked password container, raw CTR, and inspect. In-memory
// over Uint8Array (the output is byte-identical to the streaming Rust/Go ports,
// so .mahi files are cross-compatible). Async because the KDFs and HMAC are.

import { concat, equalBytes, utf8 } from "../bytes";
import { AuthError, InvalidParamsError, MalformedContainerError } from "./errors";
import { deriveFromPassword, validate } from "./kdf";
import { macTag, macVerify } from "./mac";
import { type CipherBackend, tsBackend } from "./backend";
import {
  type Header,
  type KDFParams,
  type MacId,
  type Variant,
  marshalHeader,
  readHeader,
  keyLen,
  blockLen,
  FORMAT_VERSION,
  DEFAULT_CHUNK_BYTES,
  effectiveMaxChunkBytes,
  MAX_LABEL_LEN,
  MAC_KEY_LEN,
  MAC_SKEIN,
  KDF_ARGON2ID,
  TAG_LEN,
  T256,
} from "./format";

// Re-export the typed error hierarchy so consumers of the engine can branch on
// failures with instanceof without reaching into a second module.
export { DoradoError, AuthError, MalformedContainerError, InvalidParamsError } from "./errors";

// Re-export both standard forms of key derivation, so embedders of the raw-key
// modes can stretch a password (or fetch a strong key) once and fan it out into
// per-purpose keys without reaching into the kdf module.
export { deriveFromPassword, deriveFromKey, deriveFromKeyWith, type KdfPrf } from "./kdf";

const FRAME_DOMAIN = "DRDOchnk";

export interface PasswordOptions {
  variant: Variant;
  kdf: KDFParams;
  mac: MacId;
  tweak: Uint8Array;
  chunkSize: number;
  label: Uint8Array;
}

export function defaultOptions(): PasswordOptions {
  return {
    variant: T256,
    kdf: { kind: KDF_ARGON2ID, mCost: 64 * 1024, tCost: 3, pCost: 1 },
    mac: MAC_SKEIN,
    tweak: new Uint8Array(16),
    chunkSize: DEFAULT_CHUNK_BYTES,
    label: new Uint8Array(0),
  };
}

function u32be(v: number): Uint8Array {
  return new Uint8Array([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}
function u64be(v: number): Uint8Array {
  const hi = Math.floor(v / 0x100000000);
  const lo = v % 0x100000000;
  return concat(u32be(hi), u32be(lo));
}

function frameAAD(headerBytes: Uint8Array, index: number, isLast: boolean, ct: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [new TextEncoder().encode(FRAME_DOMAIN)];
  if (index === 0) parts.push(headerBytes);
  parts.push(u64be(index), new Uint8Array([isLast ? 1 : 0]), u32be(ct.length), ct);
  return concat(...parts);
}

export async function encryptPasswordBytes(
  password: Uint8Array,
  opts: PasswordOptions,
  plaintext: Uint8Array,
  backend: CipherBackend = tsBackend,
): Promise<Uint8Array> {
  if (opts.label.length > MAX_LABEL_LEN) throw new InvalidParamsError("label too long");
  const cap = effectiveMaxChunkBytes();
  if (opts.chunkSize === 0 || opts.chunkSize > cap) {
    throw new InvalidParamsError(`invalid chunk size ${opts.chunkSize} (cap ${cap})`);
  }
  const v = opts.variant;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(blockLen(v)));
  const keymat = await deriveFromPassword(opts.kdf, password, salt, keyLen(v) + MAC_KEY_LEN);
  const encKey = keymat.subarray(0, keyLen(v));
  const macKey = keymat.subarray(keyLen(v));

  const header: Header = {
    version: FORMAT_VERSION,
    variant: v,
    kdf: opts.kdf,
    mac: opts.mac,
    chunkSize: opts.chunkSize,
    salt,
    tweak: opts.tweak,
    iv,
    label: opts.label,
  };
  const headerBytes = marshalHeader(header);

  const ct = backend.ctr(v, encKey, opts.tweak, iv, plaintext);

  const parts: Uint8Array[] = [headerBytes];
  const cs = opts.chunkSize;
  const numChunks = Math.max(1, Math.ceil(ct.length / cs));
  for (let i = 0; i < numChunks; i++) {
    const chunk = ct.subarray(i * cs, Math.min((i + 1) * cs, ct.length));
    const isLast = i === numChunks - 1;
    const tag = await macTag(backend, opts.mac, macKey, frameAAD(headerBytes, i, isLast, chunk));
    parts.push(new Uint8Array([isLast ? 1 : 0]), u32be(chunk.length), chunk, tag);
  }
  return concat(...parts);
}

export async function decryptPasswordBytes(
  password: Uint8Array,
  data: Uint8Array,
  expectedLabel?: Uint8Array,
  backend: CipherBackend = tsBackend,
): Promise<Uint8Array> {
  const { header, offset } = readHeader(data);
  if (expectedLabel !== undefined && !equalBytes(expectedLabel, header.label)) {
    throw new InvalidParamsError("container label does not match the expected label");
  }
  const headerBytes = marshalHeader(header);
  const bl = blockLen(header.variant);
  if (header.chunkSize === 0 || header.chunkSize > effectiveMaxChunkBytes() || header.chunkSize % bl !== 0) {
    throw new MalformedContainerError(`invalid chunk size ${header.chunkSize} in header`);
  }
  validate(header.kdf);
  const keymat = await deriveFromPassword(header.kdf, password, header.salt, keyLen(header.variant) + MAC_KEY_LEN);
  const encKey = keymat.subarray(0, keyLen(header.variant));
  const macKey = keymat.subarray(keyLen(header.variant));

  let pos = offset;
  let index = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    if (pos + 5 > data.length) throw new MalformedContainerError("stream ended before the final chunk (truncated)");
    const flag = data[pos];
    if (flag > 1) throw new MalformedContainerError(`invalid frame flag ${flag}`);
    const isLast = flag === 1;
    const ctLen = ((data[pos + 1] << 24) | (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4]) >>> 0;
    pos += 5;
    if (ctLen > header.chunkSize) throw new MalformedContainerError("frame length exceeds the header chunk size");
    if (pos + ctLen + TAG_LEN > data.length) throw new MalformedContainerError("truncated frame");
    const ct = data.subarray(pos, pos + ctLen);
    pos += ctLen;
    const tag = data.subarray(pos, pos + TAG_LEN);
    pos += TAG_LEN;
    if (!(await macVerify(backend, header.mac, macKey, frameAAD(headerBytes, index, isLast, ct), tag))) {
      throw new AuthError("authentication failed (wrong password, corruption, or tampering)");
    }
    chunks.push(ct.slice());
    if (isLast) break;
    if (ct.length !== header.chunkSize) throw new MalformedContainerError("non-final chunk is not full size");
    index++;
  }

  const ciphertext = concat(...chunks);
  return backend.ctr(header.variant, encKey, header.tweak, header.iv, ciphertext);
}

export interface ContainerInfo {
  version: number;
  variant: Variant;
  kdf: KDFParams;
  mac: MacId;
  chunkSize: number;
  saltLen: number;
  tweak: Uint8Array;
  label: Uint8Array;
}

export function inspect(data: Uint8Array): ContainerInfo {
  const { header } = readHeader(data);
  return {
    version: header.version,
    variant: header.variant,
    kdf: header.kdf,
    mac: header.mac,
    chunkSize: header.chunkSize,
    saltLen: header.salt.length,
    tweak: header.tweak,
    label: header.label,
  };
}

export function rawCTR(
  v: Variant,
  key: Uint8Array,
  tweak: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
  backend: CipherBackend = tsBackend,
): Uint8Array {
  if (iv.length !== blockLen(v)) throw new InvalidParamsError(`iv must be ${blockLen(v)} bytes, got ${iv.length}`);
  return backend.ctr(v, key, tweak, iv, data);
}

// ---------------------------------------------------------------------------
// Raw-key authenticated CTR (encrypt-then-MAC, caller-supplied key). Adds
// authentication on top of rawCTR's bare keystream by reusing the password
// container's frame construction, without a password or KDF. See
// ../../../docs/spec.md's "Raw-key modes" section for the byte-level spec.
// ---------------------------------------------------------------------------

// Domain separator for deriving the encryption subkey from a raw key.
const RAW_AUTH_ENC_DOMAIN = "DRDOrawE";
// Domain separator for deriving the MAC subkey from a raw key.
const RAW_AUTH_MAC_DOMAIN = "DRDOrawM";
// Domain separator mixed into every raw-authenticated frame tag. Distinct from
// FRAME_DOMAIN so a raw-mode frame's tag can never collide with or be replayed
// as a password-mode frame's tag, even under key reuse across both paths.
const RAW_FRAME_DOMAIN = "DRDOrwFr";

// Split a caller-supplied raw key into an independent encryption subkey and MAC
// subkey, each derived via domain-separated Skein-512 keyed hashing (`key` is
// the MAC key, the domain label is the message). This is deliberately not a
// password KDF: `key` is assumed to already be high-entropy (e.g. from an OS
// keychain or a CSPRNG), so no cost-parameterized stretching is needed, only
// separation into two subkeys that must not be the same bytes used for two
// different primitives.
function splitRawKey(
  v: Variant,
  key: Uint8Array,
  backend: CipherBackend,
): { encKey: Uint8Array; macKey: Uint8Array } {
  if (key.length !== keyLen(v)) {
    throw new InvalidParamsError(`raw key must be ${keyLen(v)} bytes for this variant, got ${key.length}`);
  }
  const encKey = backend.skeinMac(key, keyLen(v), utf8(RAW_AUTH_ENC_DOMAIN));
  const macKey = backend.skeinMac(key, MAC_KEY_LEN, utf8(RAW_AUTH_MAC_DOMAIN));
  return { encKey, macKey };
}

// Authenticated data for a raw-mode frame: a domain separator, the tweak and IV
// (for the first frame only, binding the parameters — raw mode has no header to
// bind them into the way the password container does), the frame index, the
// last flag, and the ciphertext. Mirrors frameAAD, substituting tweak+IV for
// the header.
function rawFrameAAD(tweak: Uint8Array, iv: Uint8Array, index: number, isLast: boolean, ct: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [utf8(RAW_FRAME_DOMAIN)];
  if (index === 0) parts.push(tweak, iv);
  parts.push(u64be(index), new Uint8Array([isLast ? 1 : 0]), u32be(ct.length), ct);
  return concat(...parts);
}

// Validate the IV and chunk size shared by the raw-authenticated encrypt and
// decrypt paths.
function validateRawAuthParams(v: Variant, iv: Uint8Array, chunkSize: number): void {
  const bl = blockLen(v);
  if (iv.length !== bl) throw new InvalidParamsError(`iv must be ${bl} bytes for this variant, got ${iv.length}`);
  if (chunkSize === 0 || chunkSize % bl !== 0) {
    throw new InvalidParamsError(`chunk size must be a positive multiple of the block size (${bl}), got ${chunkSize}`);
  }
}

/**
 * Encrypt-then-MAC over CTR keystream with a caller-supplied key: no password,
 * no KDF (see {@link splitRawKey}). Data is authenticated in fixed-size chunks,
 * reusing the same frame construction as the password container, so truncation,
 * reordering, and dropped chunks are all rejected on decryption exactly as they
 * are there. There is no header: the caller must supply the same `variant`,
 * `tweak`, `iv`, `mac`, and `chunkSize` on decrypt as were used to encrypt, and
 * remember them out of band (nothing here is recoverable from the ciphertext
 * alone, matching {@link rawCTR}'s no-header philosophy).
 */
export async function encryptRawAuthenticatedBytes(
  variant: Variant,
  key: Uint8Array,
  tweak: Uint8Array,
  iv: Uint8Array,
  mac: MacId,
  chunkSize: number,
  plaintext: Uint8Array,
  backend: CipherBackend = tsBackend,
): Promise<Uint8Array> {
  validateRawAuthParams(variant, iv, chunkSize);
  const { encKey, macKey } = splitRawKey(variant, key, backend);
  const ct = backend.ctr(variant, encKey, tweak, iv, plaintext);

  const parts: Uint8Array[] = [];
  const cs = chunkSize;
  const numChunks = Math.max(1, Math.ceil(ct.length / cs));
  for (let i = 0; i < numChunks; i++) {
    const chunk = ct.subarray(i * cs, Math.min((i + 1) * cs, ct.length));
    const isLast = i === numChunks - 1;
    const tag = await macTag(backend, mac, macKey, rawFrameAAD(tweak, iv, i, isLast, chunk));
    parts.push(new Uint8Array([isLast ? 1 : 0]), u32be(chunk.length), chunk, tag);
  }
  return concat(...parts);
}

/**
 * Decrypt an {@link encryptRawAuthenticatedBytes} stream. Each frame's tag is
 * verified (constant-time compare) before that frame is decrypted, so a wrong
 * key or a corrupted or tampered stream throws {@link AuthError} instead of
 * silently producing garbage or attacker-influenced plaintext — the failure
 * mode {@link rawCTR} cannot detect.
 */
export async function decryptRawAuthenticatedBytes(
  variant: Variant,
  key: Uint8Array,
  tweak: Uint8Array,
  iv: Uint8Array,
  mac: MacId,
  chunkSize: number,
  data: Uint8Array,
  backend: CipherBackend = tsBackend,
): Promise<Uint8Array> {
  validateRawAuthParams(variant, iv, chunkSize);
  const cap = effectiveMaxChunkBytes();
  if (chunkSize > cap) throw new InvalidParamsError(`chunk size ${chunkSize} exceeds the accepted maximum`);
  const { encKey, macKey } = splitRawKey(variant, key, backend);

  let pos = 0;
  let index = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    if (pos + 5 > data.length) throw new MalformedContainerError("stream ended before the final chunk (truncated)");
    const flag = data[pos];
    if (flag > 1) throw new MalformedContainerError(`invalid frame flag ${flag}`);
    const isLast = flag === 1;
    const ctLen = ((data[pos + 1] << 24) | (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4]) >>> 0;
    pos += 5;
    if (ctLen > chunkSize) throw new MalformedContainerError("frame length exceeds the chunk size");
    if (pos + ctLen + TAG_LEN > data.length) throw new MalformedContainerError("truncated frame");
    const ct = data.subarray(pos, pos + ctLen);
    pos += ctLen;
    const tag = data.subarray(pos, pos + TAG_LEN);
    pos += TAG_LEN;
    if (!(await macVerify(backend, mac, macKey, rawFrameAAD(tweak, iv, index, isLast, ct), tag))) {
      throw new AuthError("authentication failed (wrong key, corruption, or tampering)");
    }
    chunks.push(ct.slice());
    if (isLast) break;
    if (ct.length !== chunkSize) throw new MalformedContainerError("non-final chunk is not full size");
    index++;
  }

  const ciphertext = concat(...chunks);
  return backend.ctr(variant, encKey, tweak, iv, ciphertext);
}

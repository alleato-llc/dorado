// The authenticated chunked password container, raw CTR, and inspect. In-memory
// over Uint8Array (the output is byte-identical to the streaming Rust/Go ports,
// so .mahi files are cross-compatible). Async because the KDFs and HMAC are.

import { concat, equalBytes } from "../bytes";
import { derive, validate } from "./kdf";
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
  MAX_CHUNK_BYTES,
  MAX_LABEL_LEN,
  MAC_KEY_LEN,
  MAC_SKEIN,
  KDF_ARGON2ID,
  TAG_LEN,
  T256,
} from "./format";

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
  if (opts.label.length > MAX_LABEL_LEN) throw new Error("label too long");
  const v = opts.variant;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(blockLen(v)));
  const keymat = await derive(opts.kdf, password, salt, keyLen(v) + MAC_KEY_LEN);
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
    throw new Error("container label does not match the expected label");
  }
  const headerBytes = marshalHeader(header);
  const bl = blockLen(header.variant);
  if (header.chunkSize === 0 || header.chunkSize > MAX_CHUNK_BYTES || header.chunkSize % bl !== 0) {
    throw new Error(`invalid chunk size ${header.chunkSize} in header`);
  }
  validate(header.kdf);
  const keymat = await derive(header.kdf, password, header.salt, keyLen(header.variant) + MAC_KEY_LEN);
  const encKey = keymat.subarray(0, keyLen(header.variant));
  const macKey = keymat.subarray(keyLen(header.variant));

  let pos = offset;
  let index = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    if (pos + 5 > data.length) throw new Error("stream ended before the final chunk (truncated)");
    const flag = data[pos];
    if (flag > 1) throw new Error(`invalid frame flag ${flag}`);
    const isLast = flag === 1;
    const ctLen = ((data[pos + 1] << 24) | (data[pos + 2] << 16) | (data[pos + 3] << 8) | data[pos + 4]) >>> 0;
    pos += 5;
    if (ctLen > header.chunkSize) throw new Error("frame length exceeds the header chunk size");
    if (pos + ctLen + TAG_LEN > data.length) throw new Error("truncated frame");
    const ct = data.subarray(pos, pos + ctLen);
    pos += ctLen;
    const tag = data.subarray(pos, pos + TAG_LEN);
    pos += TAG_LEN;
    if (!(await macVerify(backend, header.mac, macKey, frameAAD(headerBytes, index, isLast, ct), tag))) {
      throw new Error("authentication failed (wrong password, corruption, or tampering)");
    }
    chunks.push(ct.slice());
    if (isLast) break;
    if (ct.length !== header.chunkSize) throw new Error("non-final chunk is not full size");
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
  if (iv.length !== blockLen(v)) throw new Error(`iv must be ${blockLen(v)} bytes, got ${iv.length}`);
  return backend.ctr(v, key, tweak, iv, data);
}

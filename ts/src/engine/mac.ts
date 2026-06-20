// The MAC menu: Skein-512 (default) and BLAKE3 from the selected backend,
// HMAC-SHA256 via Web Crypto (isomorphic across Node and the browser).

import { equalBytes } from "../bytes";
import { type CipherBackend } from "./backend";
import { type MacId, MAC_SKEIN, MAC_HMAC, MAC_BLAKE3, TAG_LEN } from "./format";

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  // The casts work around a TS 5.7 Uint8Array<ArrayBufferLike> vs BufferSource
  // quirk; a Uint8Array is a valid BufferSource at runtime.
  const k = await crypto.subtle.importKey(
    "raw",
    key as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as unknown as BufferSource));
}

export async function macTag(backend: CipherBackend, mac: MacId, macKey: Uint8Array, signed: Uint8Array): Promise<Uint8Array> {
  switch (mac) {
    case MAC_SKEIN:
      return backend.skeinMac(macKey, TAG_LEN, signed);
    case MAC_HMAC:
      return await hmacSha256(macKey, signed);
    case MAC_BLAKE3:
      return backend.blake3KeyedMac(macKey, TAG_LEN, signed);
  }
}

export async function macVerify(
  backend: CipherBackend,
  mac: MacId,
  macKey: Uint8Array,
  signed: Uint8Array,
  received: Uint8Array,
): Promise<boolean> {
  return equalBytes(await macTag(backend, mac, macKey, signed), received);
}

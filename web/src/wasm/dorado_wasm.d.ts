/* tslint:disable */
/* eslint-disable */

export function blake3_hash(out_len: number, input: Uint8Array): Uint8Array;

export function blake3_keyed_mac(key: Uint8Array, out_len: number, input: Uint8Array): Uint8Array;

export function ctr1024(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;

export function ctr256(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;

export function ctr512(key: Uint8Array, tweak: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;

export function skein_hash(out_len: number, msg: Uint8Array): Uint8Array;

export function skein_mac(key: Uint8Array, out_len: number, msg: Uint8Array): Uint8Array;

export function threefish256_decrypt_block(key: Uint8Array, tweak: Uint8Array, block: Uint8Array): Uint8Array;

export function threefish256_encrypt_block(key: Uint8Array, tweak: Uint8Array, block: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly blake3_hash: (a: number, b: number, c: number) => [number, number];
    readonly blake3_keyed_mac: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly ctr1024: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly ctr256: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly ctr512: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly skein_hash: (a: number, b: number, c: number) => [number, number];
    readonly skein_mac: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly threefish256_decrypt_block: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly threefish256_encrypt_block: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;

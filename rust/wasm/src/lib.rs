//! WebAssembly bindings for the dorado cipher and hashes. This compiles the
//! verified Rust implementation to WASM, so the TS engine (Node and browser) can
//! run the cipher's secret arithmetic in WASM linear memory and the WASM value
//! stack instead of the JavaScript GC heap. Output is identical to the native
//! Rust/Go/TS ports, so .mahi files stay cross-compatible.

use dorado::{Threefish1024, Threefish256, Threefish512};
use wasm_bindgen::prelude::*;

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    b.try_into().expect("wasm binding: wrong byte length")
}

// --- Threefish block (used by the known-answer cross-check) ---

#[wasm_bindgen]
pub fn threefish256_encrypt_block(key: &[u8], tweak: &[u8], block: &[u8]) -> Vec<u8> {
    let c = Threefish256::new(&arr(key), &arr(tweak));
    let mut b = arr::<32>(block);
    c.encrypt_block(&mut b);
    b.to_vec()
}

#[wasm_bindgen]
pub fn threefish256_decrypt_block(key: &[u8], tweak: &[u8], block: &[u8]) -> Vec<u8> {
    let c = Threefish256::new(&arr(key), &arr(tweak));
    let mut b = arr::<32>(block);
    c.decrypt_block(&mut b);
    b.to_vec()
}

// --- CTR (encrypt and decrypt are the same operation) ---

#[wasm_bindgen]
pub fn ctr256(key: &[u8], tweak: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let c = Threefish256::new(&arr(key), &arr(tweak));
    let mut d = data.to_vec();
    c.ctr_apply(&arr(iv), &mut d);
    d
}

#[wasm_bindgen]
pub fn ctr512(key: &[u8], tweak: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let c = Threefish512::new(&arr(key), &arr(tweak));
    let mut d = data.to_vec();
    c.ctr_apply(&arr(iv), &mut d);
    d
}

#[wasm_bindgen]
pub fn ctr1024(key: &[u8], tweak: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let c = Threefish1024::new(&arr(key), &arr(tweak));
    let mut d = data.to_vec();
    c.ctr_apply(&arr(iv), &mut d);
    d
}

// --- Hashes / MACs ---

#[wasm_bindgen]
pub fn skein_hash(out_len: usize, msg: &[u8]) -> Vec<u8> {
    dorado::skein::hash(out_len, msg)
}

#[wasm_bindgen]
pub fn skein_mac(key: &[u8], out_len: usize, msg: &[u8]) -> Vec<u8> {
    dorado::skein::mac(key, out_len, msg)
}

#[wasm_bindgen]
pub fn blake3_hash(out_len: usize, input: &[u8]) -> Vec<u8> {
    dorado::blake3::hash(out_len, input)
}

#[wasm_bindgen]
pub fn blake3_keyed_mac(key: &[u8], out_len: usize, input: &[u8]) -> Vec<u8> {
    dorado::blake3::keyed_mac(&arr(key), out_len, input)
}

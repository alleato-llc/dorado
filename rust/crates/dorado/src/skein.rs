//! Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI (Unique
//! Block Iteration), from scratch. This is the hash function Threefish was
//! designed to power: it threads message blocks through Threefish, using the
//! tweak to encode each block's position and type.
//!
//! Verified differentially against the RustCrypto `skein` crate (see tests).

use alloc::vec::Vec;

use crate::Threefish512;

const BLOCK: usize = 64; // Skein-512 block size in bytes.

// UBI block type values (the 6-bit type field of the tweak).
const T_KEY: u64 = 0;
const T_CFG: u64 = 4;
const T_MSG: u64 = 48;
const T_OUT: u64 = 63;

/// Build the 128-bit UBI tweak (as 16 little-endian bytes) for a block at byte
/// `position` of a UBI pass of type `ty`, with the first/final flags.
///
/// Layout: bits 0-95 are the position (we only ever use the low 64), bits
/// 120-125 the type, bit 126 first, bit 127 final.
fn tweak(position: u64, ty: u64, first: bool, last: bool) -> [u8; 16] {
    let mut t1 = ty << 56;
    if first {
        t1 |= 1 << 62;
    }
    if last {
        t1 |= 1 << 63;
    }
    let mut tw = [0u8; 16];
    tw[0..8].copy_from_slice(&position.to_le_bytes());
    tw[8..16].copy_from_slice(&t1.to_le_bytes());
    tw
}

/// One UBI pass: chain `msg` into the 64-byte chaining value `g` under block
/// type `ty`. An empty message processes a single zero block at position 0.
fn ubi(g: &mut [u8; 64], msg: &[u8], ty: u64) {
    let total = msg.len();
    let mut offset = 0;
    let mut position: u64 = 0;
    let mut first = true;
    loop {
        let take = (total - offset).min(BLOCK);
        let mut block = [0u8; 64];
        block[..take].copy_from_slice(&msg[offset..offset + take]);
        position += take as u64;
        offset += take;
        let last = offset >= total;

        // Threefish-512 keyed by the current chaining value, tweaked by position
        // and type; then xor the plaintext block back in (Matyas-Meyer-Oseas).
        let cipher = Threefish512::new(g, &tweak(position, ty, first, last));
        let mut enc = block;
        cipher.encrypt_block(&mut enc);
        for i in 0..64 {
            g[i] = enc[i] ^ block[i];
        }

        first = false;
        if last {
            break;
        }
    }
}

/// The 32-byte Skein configuration block for an output of `out_bits` bits.
fn config_block(out_bits: u64) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[0..4].copy_from_slice(b"SHA3"); // schema identifier
    c[4] = 1; // version 1 (16-bit little-endian)
    c[8..16].copy_from_slice(&out_bits.to_le_bytes());
    c
}

/// Produce `out_len` output bytes from the final chaining value by running the
/// output UBI over an incrementing counter.
fn output(g: &[u8; 64], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u64 = 0;
    while out.len() < out_len {
        let mut block = *g;
        ubi(&mut block, &counter.to_le_bytes(), T_OUT);
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Skein-512 hash of `msg` with `out_len` output bytes.
pub fn hash(out_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut g = [0u8; 64];
    ubi(&mut g, &config_block((out_len as u64) * 8), T_CFG);
    ubi(&mut g, msg, T_MSG);
    output(&g, out_len)
}

/// Skein-512 MAC: a keyed hash. Processes `key` through a Key UBI before the
/// configuration and message, producing `out_len` tag bytes.
pub fn mac(key: &[u8], out_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut g = [0u8; 64];
    if !key.is_empty() {
        ubi(&mut g, key, T_KEY);
    }
    ubi(&mut g, &config_block((out_len as u64) * 8), T_CFG);
    ubi(&mut g, msg, T_MSG);
    output(&g, out_len)
}

#[cfg(test)]
mod tests;

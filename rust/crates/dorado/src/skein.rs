//! Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI (Unique
//! Block Iteration), from scratch. This is the hash function Threefish was
//! designed to power: it threads message blocks through Threefish, using the
//! tweak to encode each block's position and type.
//!
//! Verified differentially against the RustCrypto `skein` crate (see tests).

#[cfg(feature = "alloc")]
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

/// Fill `out` from the final chaining value by running the output UBI over an
/// incrementing counter. Allocation-free: writes directly into the caller's
/// buffer.
fn output_into(g: &[u8; 64], out: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut written = 0;
    while written < out.len() {
        let mut block = *g;
        ubi(&mut block, &counter.to_le_bytes(), T_OUT);
        let n = core::cmp::min(BLOCK, out.len() - written);
        out[written..written + n].copy_from_slice(&block[..n]);
        written += n;
        counter += 1;
    }
}

/// Incremental Skein-512 hash/MAC. Feed the message with `update` (in any
/// chunking) and write the digest with `finalize_into`. Allocation-free and
/// fixed-size, so it can hash an input larger than memory on a heap-less device.
///
/// The output length must be fixed at construction, because Skein folds it into
/// the configuration block that seeds the chaining value: `finalize_into` writes
/// exactly the `out_len` passed to `new`/`new_mac`.
pub struct Skein512 {
    g: [u8; 64],
    out_len: usize,
    /// Message bytes not yet committed to a UBI block.
    buffer: [u8; BLOCK],
    buffer_len: usize,
    /// Total message bytes committed so far (the UBI tweak position).
    position: u64,
    /// True until the first message block is processed.
    first: bool,
}

impl Skein512 {
    /// Start an unkeyed hash producing `out_len` bytes.
    pub fn new(out_len: usize) -> Self {
        let mut g = [0u8; 64];
        ubi(&mut g, &config_block((out_len as u64) * 8), T_CFG);
        Self::with_config(g, out_len)
    }

    /// Start a keyed MAC producing `out_len` bytes, absorbing `key` first.
    pub fn new_mac(key: &[u8], out_len: usize) -> Self {
        let mut g = [0u8; 64];
        if !key.is_empty() {
            ubi(&mut g, key, T_KEY);
        }
        ubi(&mut g, &config_block((out_len as u64) * 8), T_CFG);
        Self::with_config(g, out_len)
    }

    fn with_config(g: [u8; 64], out_len: usize) -> Self {
        Skein512 {
            g,
            out_len,
            buffer: [0u8; BLOCK],
            buffer_len: 0,
            position: 0,
            first: true,
        }
    }

    /// Commit one message block of `nbytes` real bytes (`block` zero-padded to a
    /// full block). The last block of the message must set `last`.
    fn commit_block(&mut self, block: &[u8; BLOCK], nbytes: usize, last: bool) {
        self.position += nbytes as u64;
        let cipher = Threefish512::new(&self.g, &tweak(self.position, T_MSG, self.first, last));
        let mut enc = *block;
        cipher.encrypt_block(&mut enc);
        for i in 0..BLOCK {
            self.g[i] = enc[i] ^ block[i];
        }
        self.first = false;
    }

    /// Feed message bytes. The final block is held back (never processed here),
    /// since only `finalize_into` knows which block is last.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // Top off a partial buffer; flush it as a non-final block only once we
        // know more data follows it.
        if self.buffer_len > 0 {
            let take = (BLOCK - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len == BLOCK && !data.is_empty() {
                let full = self.buffer;
                self.commit_block(&full, BLOCK, false);
                self.buffer_len = 0;
            }
        }
        // Commit whole blocks straight from the input, but always keep the last
        // <= BLOCK bytes back for the final block.
        while data.len() > BLOCK {
            let block: [u8; BLOCK] = data[..BLOCK]
                .try_into()
                .expect("invariant: data[..BLOCK] is exactly BLOCK bytes");
            self.commit_block(&block, BLOCK, false);
            data = &data[BLOCK..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Process the final message block and write the digest into `out`, which
    /// must be exactly `out_len` bytes.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.out_len, "out length must equal out_len");
        let mut block = [0u8; BLOCK];
        block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        self.commit_block(&block, self.buffer_len, true);
        output_into(&self.g, out);
    }
}

/// Skein-512 hash of `msg` into the caller-provided `out` buffer. The output
/// length is `out.len()`. Allocation-free (works without `alloc`).
pub fn hash_into(out: &mut [u8], msg: &[u8]) {
    let mut h = Skein512::new(out.len());
    h.update(msg);
    h.finalize_into(out);
}

/// Skein-512 MAC (keyed hash) into the caller-provided `out` buffer. Processes
/// `key` through a Key UBI first. Allocation-free (works without `alloc`).
pub fn mac_into(out: &mut [u8], key: &[u8], msg: &[u8]) {
    let mut h = Skein512::new_mac(key, out.len());
    h.update(msg);
    h.finalize_into(out);
}

/// Skein-512 hash of `msg` with `out_len` output bytes. Convenience wrapper over
/// [`hash_into`] that allocates the result (requires the `alloc` feature).
#[cfg(feature = "alloc")]
pub fn hash(out_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; out_len];
    hash_into(&mut out, msg);
    out
}

/// Skein-512 MAC: a keyed hash producing `out_len` tag bytes. Convenience
/// wrapper over [`mac_into`] that allocates (requires the `alloc` feature).
#[cfg(feature = "alloc")]
pub fn mac(key: &[u8], out_len: usize, msg: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; out_len];
    mac_into(&mut out, key, msg);
    out
}

#[cfg(test)]
mod tests;

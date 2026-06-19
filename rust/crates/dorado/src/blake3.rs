//! BLAKE3 hash and keyed MAC, implemented from scratch and verified
//! differentially against the `blake3` crate.
//!
//! BLAKE3 is a Merkle-tree hash: the input is split into 1024-byte chunks, each
//! chunk is compressed block by block into a chaining value, and the chunk
//! chaining values are combined pairwise into parent nodes up to a single root.
//! Domain-separation flags keep chunks, parents, the root, and keyed mode
//! distinct. The compression is a BLAKE2s-style ARX mixing function.

use alloc::vec::Vec;

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
#[allow(clippy::too_many_arguments)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// The BLAKE3 compression function: returns all 16 output words.
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    for round in 0..7 {
        g(&mut state, 0, 4, 8, 12, m[0], m[1]);
        g(&mut state, 1, 5, 9, 13, m[2], m[3]);
        g(&mut state, 2, 6, 10, 14, m[4], m[5]);
        g(&mut state, 3, 7, 11, 15, m[6], m[7]);
        g(&mut state, 0, 5, 10, 15, m[8], m[9]);
        g(&mut state, 1, 6, 11, 12, m[10], m[11]);
        g(&mut state, 2, 7, 8, 13, m[12], m[13]);
        g(&mut state, 3, 4, 9, 14, m[14], m[15]);
        if round < 6 {
            let mut permuted = [0u32; 16];
            for i in 0..16 {
                permuted[i] = m[MSG_PERMUTATION[i]];
            }
            m = permuted;
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn words_from_block(bytes: &[u8]) -> [u32; 16] {
    let mut padded = [0u8; BLOCK_LEN];
    padded[..bytes.len()].copy_from_slice(bytes);
    let mut words = [0u32; 16];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(padded[i * 4..i * 4 + 4].try_into().unwrap());
    }
    words
}

/// A node's output: enough to either produce a chaining value (intermediate
/// node) or extendable output bytes (the root).
struct Output {
    input_cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let full = compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        );
        full[..8].try_into().unwrap()
    }

    fn root_output(&self, out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let mut counter = 0u64;
        while out.len() < out_len {
            let words = compress(
                &self.input_cv,
                &self.block,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            for w in &words {
                out.extend_from_slice(&w.to_le_bytes());
            }
            counter += 1;
        }
        out.truncate(out_len);
        out
    }
}

/// Process one chunk (up to CHUNK_LEN bytes) into its final-block `Output`.
fn chunk_output(chunk: &[u8], chunk_counter: u64, key: &[u32; 8], base_flags: u32) -> Output {
    let mut cv = *key;
    let n_blocks = chunk.len().div_ceil(BLOCK_LEN).max(1);
    for i in 0..n_blocks {
        let start = i * BLOCK_LEN;
        let end = (start + BLOCK_LEN).min(chunk.len());
        let block_bytes = &chunk[start..end];
        let mut flags = base_flags;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == n_blocks - 1 {
            return Output {
                input_cv: cv,
                block: words_from_block(block_bytes),
                counter: chunk_counter,
                block_len: block_bytes.len() as u32,
                flags: flags | CHUNK_END,
            };
        }
        let full = compress(
            &cv,
            &words_from_block(block_bytes),
            chunk_counter,
            BLOCK_LEN as u32,
            flags,
        );
        cv = full[..8].try_into().unwrap();
    }
    unreachable!("a chunk always has at least one block")
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: &[u32; 8], base_flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output {
        input_cv: *key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: base_flags | PARENT,
    }
}

/// The largest power of two not exceeding `n`.
fn largest_power_of_two_leq(n: usize) -> usize {
    let mut p = 1;
    while p * 2 <= n {
        p *= 2;
    }
    p
}

/// The byte boundary at which to split a multi-chunk input: the largest
/// power-of-two number of whole chunks strictly less than the total.
fn left_len(content_len: usize) -> usize {
    let full_chunks = (content_len - 1) / CHUNK_LEN;
    largest_power_of_two_leq(full_chunks) * CHUNK_LEN
}

/// Hash a subtree to a chaining value (never the root).
fn subtree_cv(input: &[u8], chunk_counter: u64, key: &[u32; 8], flags: u32) -> [u32; 8] {
    if input.len() <= CHUNK_LEN {
        return chunk_output(input, chunk_counter, key, flags).chaining_value();
    }
    let mid = left_len(input.len());
    let left = subtree_cv(&input[..mid], chunk_counter, key, flags);
    let right = subtree_cv(
        &input[mid..],
        chunk_counter + (mid / CHUNK_LEN) as u64,
        key,
        flags,
    );
    parent_output(left, right, key, flags).chaining_value()
}

fn hash_internal(input: &[u8], key: &[u32; 8], flags: u32, out_len: usize) -> Vec<u8> {
    let output = if input.len() <= CHUNK_LEN {
        chunk_output(input, 0, key, flags)
    } else {
        let mid = left_len(input.len());
        let left = subtree_cv(&input[..mid], 0, key, flags);
        let right = subtree_cv(&input[mid..], (mid / CHUNK_LEN) as u64, key, flags);
        parent_output(left, right, key, flags)
    };
    output.root_output(out_len)
}

/// BLAKE3 hash of `input`, producing `out_len` bytes (XOF for `out_len > 32`).
pub fn hash(out_len: usize, input: &[u8]) -> Vec<u8> {
    hash_internal(input, &IV, 0, out_len)
}

/// BLAKE3 keyed MAC under a 32-byte `key`, producing `out_len` tag bytes.
pub fn keyed_mac(key: &[u8; 32], out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut key_words = [0u32; 8];
    for (i, w) in key_words.iter_mut().enumerate() {
        *w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    hash_internal(input, &key_words, KEYED_HASH, out_len)
}

#[cfg(test)]
mod tests;

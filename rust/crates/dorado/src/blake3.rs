//! BLAKE3 hash and keyed MAC, implemented from scratch and verified
//! differentially against the `blake3` crate.
//!
//! BLAKE3 is a Merkle-tree hash: the input is split into 1024-byte chunks, each
//! chunk is compressed block by block into a chaining value, and the chunk
//! chaining values are combined pairwise into parent nodes up to a single root.
//! Domain-separation flags keep chunks, parents, the root, and keyed mode
//! distinct. The compression is a BLAKE2s-style ARX mixing function.

#[cfg(feature = "alloc")]
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

    /// Fill `out` with the root output (an extendable-output function for
    /// `out.len() > 32`). Allocation-free: writes into the caller's buffer.
    fn root_output_into(&self, out: &mut [u8]) {
        let mut counter = 0u64;
        let mut written = 0;
        while written < out.len() {
            let words = compress(
                &self.input_cv,
                &self.block,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            for w in &words {
                if written >= out.len() {
                    break;
                }
                let bytes = w.to_le_bytes();
                let n = core::cmp::min(4, out.len() - written);
                out[written..written + n].copy_from_slice(&bytes[..n]);
                written += n;
            }
            counter += 1;
        }
    }
}

/// One chunk being absorbed block by block. Holds only fixed-size state, so a
/// chunk can be built incrementally without keeping its 1024 bytes around.
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: u64,
    flags: u32,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            cv: *key,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len
    }

    /// CHUNK_START applies only to a chunk's first block.
    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // Compress a full block only once we know more data follows it, so
            // the final block of the chunk is handled by `output` (CHUNK_END).
            if self.block_len == BLOCK_LEN {
                let block_words = words_from_block(&self.block);
                let out = compress(
                    &self.cv,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.cv = out[..8].try_into().unwrap();
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = core::cmp::min(BLOCK_LEN - self.block_len, input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block: words_from_block(&self.block[..self.block_len]),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
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

fn parent_cv(left: [u32; 8], right: [u32; 8], key: &[u32; 8], flags: u32) -> [u32; 8] {
    parent_output(left, right, key, flags).chaining_value()
}

/// Incremental BLAKE3 hash/MAC: a chunk-stack streaming hasher. Feed input with
/// `update` (in any chunking) and write the digest with `finalize_into`.
/// Allocation-free and fixed-size, so it can hash an input larger than memory.
/// `finalize_into` writes any length (an extendable-output function for more
/// than 32 bytes) and may be called more than once.
pub struct Hasher {
    chunk_state: ChunkState,
    key: [u32; 8],
    // The subtree-chaining-value stack. BLAKE3's maximum input is 2^64 bytes,
    // so the tree is at most 54 levels deep.
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: usize,
    flags: u32,
}

impl Hasher {
    /// Start an unkeyed hash.
    pub fn new() -> Self {
        Self::with_key(IV, 0)
    }

    /// Start a keyed MAC under a 32-byte `key`.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        for (i, w) in key_words.iter_mut().enumerate() {
            *w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        Self::with_key(key_words, KEYED_HASH)
    }

    fn with_key(key: [u32; 8], flags: u32) -> Self {
        Hasher {
            chunk_state: ChunkState::new(&key, 0, flags),
            key,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_stack(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    fn pop_stack(&mut self) -> [u32; 8] {
        self.cv_stack_len -= 1;
        self.cv_stack[self.cv_stack_len]
    }

    /// Merge a finished chunk's chaining value into the stack: combine with the
    /// top of the stack while the running chunk count is even, then push. This
    /// builds the same tree as the recursive whole-input form.
    fn add_chunk_cv(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let left = self.pop_stack();
            new_cv = parent_cv(left, new_cv, &self.key, self.flags);
            total_chunks >>= 1;
        }
        self.push_stack(new_cv);
    }

    /// Feed input bytes (any chunking).
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_cv(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key, total_chunks, self.flags);
            }
            let take = core::cmp::min(CHUNK_LEN - self.chunk_state.len(), input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Write the digest into `out` (any length; an XOF for `out.len() > 32`).
    pub fn finalize_into(&self, out: &mut [u8]) {
        // Fold the current chunk against the stack from the top down; the last
        // parent produced is the root.
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack_len;
        while remaining > 0 {
            remaining -= 1;
            output = parent_output(
                self.cv_stack[remaining],
                output.chaining_value(),
                &self.key,
                self.flags,
            );
        }
        output.root_output_into(out);
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// BLAKE3 hash of `input` into the caller-provided `out` buffer (an
/// extendable-output function for `out.len() > 32`). Allocation-free.
pub fn hash_into(out: &mut [u8], input: &[u8]) {
    let mut h = Hasher::new();
    h.update(input);
    h.finalize_into(out);
}

/// BLAKE3 keyed MAC under a 32-byte `key`, into the caller-provided `out`
/// buffer. Allocation-free (works without `alloc`).
pub fn keyed_mac_into(out: &mut [u8], key: &[u8; 32], input: &[u8]) {
    let mut h = Hasher::new_keyed(key);
    h.update(input);
    h.finalize_into(out);
}

/// BLAKE3 hash of `input`, producing `out_len` bytes (XOF for `out_len > 32`).
/// Convenience wrapper over [`hash_into`] (requires the `alloc` feature).
#[cfg(feature = "alloc")]
pub fn hash(out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; out_len];
    hash_into(&mut out, input);
    out
}

/// BLAKE3 keyed MAC under a 32-byte `key`, producing `out_len` tag bytes.
/// Convenience wrapper over [`keyed_mac_into`] (requires the `alloc` feature).
#[cfg(feature = "alloc")]
pub fn keyed_mac(key: &[u8; 32], out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; out_len];
    keyed_mac_into(&mut out, key, input);
    out
}

#[cfg(test)]
mod tests;

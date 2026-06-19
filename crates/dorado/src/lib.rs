//! Dorado — a from-scratch implementation of the Threefish tweakable block
//! cipher, the cipher at the core of the Skein hash function.
//!
//! Supports all three block sizes: 256, 512, and 1024 bits. The design is pure
//! ARX (add / rotate / xor), so there are no S-boxes or lookup tables, and a
//! straightforward implementation like this one is already effectively
//! constant-time on typical hardware.
//!
//! This implements Threefish as standardized in the Skein 1.3 spec, including
//! the round-3 NIST tweak (the key-schedule constant C240 below).
//!
//! NOTE: This is an educational implementation. For production use, prefer an
//! audited crate.

#![forbid(unsafe_code)]

/// The largest state width (Nw), for the 1024-bit variant. Used to size the
/// fixed permutation scratch buffer so the round loop needs no heap allocation.
const MAX_NW: usize = 16;

/// Key-schedule constant (Skein 1.3). Guarantees the extended key word is never
/// all-zero and frustrates rotational cryptanalysis.
const C240: u64 = 0x1BD1_1BDA_A9FC_1A22;

// ---------------------------------------------------------------------------
// Generic ARX engine, operating on `&mut [u64]` state of length Nw.
// ---------------------------------------------------------------------------

/// Inject subkey `s` into the state (mod 2^64, word-wise).
///
/// `ek` is the extended key (Nw + 1 words); `et` is the extended tweak (3 words).
#[inline]
fn add_subkey(state: &mut [u64], ek: &[u64], et: &[u64], s: usize) {
    let nw = state.len();
    for i in 0..nw {
        let mut k = ek[(s + i) % (nw + 1)];
        if i == nw - 3 {
            k = k.wrapping_add(et[s % 3]);
        } else if i == nw - 2 {
            k = k.wrapping_add(et[(s + 1) % 3]);
        } else if i == nw - 1 {
            k = k.wrapping_add(s as u64);
        }
        state[i] = state[i].wrapping_add(k);
    }
}

/// Inverse of `add_subkey` (subtract mod 2^64).
#[inline]
fn sub_subkey(state: &mut [u64], ek: &[u64], et: &[u64], s: usize) {
    let nw = state.len();
    for i in 0..nw {
        let mut k = ek[(s + i) % (nw + 1)];
        if i == nw - 3 {
            k = k.wrapping_add(et[s % 3]);
        } else if i == nw - 2 {
            k = k.wrapping_add(et[(s + 1) % 3]);
        } else if i == nw - 1 {
            k = k.wrapping_add(s as u64);
        }
        state[i] = state[i].wrapping_sub(k);
    }
}

/// Encrypt one block in place.
///
/// `rot[lane][r % 8]` is the rotation constant for round `r`, MIX lane `lane`.
/// `perm[i]` selects which MIX-output word becomes output word `i`.
fn encrypt(
    state: &mut [u64],
    ek: &[u64],
    et: &[u64],
    rot: &[[u32; 8]],
    perm: &[usize],
    rounds: usize,
) {
    let nw = state.len();
    // Fixed-size stack scratch (sliced to `nw`) so there is no per-call heap
    // allocation; CTR encrypts one block per output block.
    let mut scratch = [0u64; MAX_NW];

    for r in 0..rounds {
        if r % 4 == 0 {
            add_subkey(state, ek, et, r / 4);
        }
        // MIX every adjacent pair of words.
        for j in 0..nw / 2 {
            let x0 = state[2 * j];
            let x1 = state[2 * j + 1];
            let y0 = x0.wrapping_add(x1);
            let y1 = x1.rotate_left(rot[j][r % 8]) ^ y0;
            state[2 * j] = y0;
            state[2 * j + 1] = y1;
        }
        // Permute: output[i] = mix_output[perm[i]].
        for i in 0..nw {
            scratch[i] = state[perm[i]];
        }
        state.copy_from_slice(&scratch[..nw]);
    }
    // Final subkey.
    add_subkey(state, ek, et, rounds / 4);
}

/// Decrypt one block in place (exact inverse of `encrypt`).
fn decrypt(
    state: &mut [u64],
    ek: &[u64],
    et: &[u64],
    rot: &[[u32; 8]],
    perm: &[usize],
    rounds: usize,
) {
    let nw = state.len();
    let mut scratch = [0u64; MAX_NW];

    sub_subkey(state, ek, et, rounds / 4);
    for r in (0..rounds).rev() {
        // Inverse permute: scratch[perm[i]] = state[i].
        for i in 0..nw {
            scratch[perm[i]] = state[i];
        }
        state.copy_from_slice(&scratch[..nw]);
        // Inverse MIX.
        for j in 0..nw / 2 {
            let y0 = state[2 * j];
            let y1 = state[2 * j + 1];
            let x1 = (y1 ^ y0).rotate_right(rot[j][r % 8]);
            let x0 = y0.wrapping_sub(x1);
            state[2 * j] = x0;
            state[2 * j + 1] = x1;
        }
        if r % 4 == 0 {
            sub_subkey(state, ek, et, r / 4);
        }
    }
}

/// Build the extended key: Nw key words plus C240 ^ (XOR of all key words).
fn extend_key(key: &[u64], ek: &mut [u64]) {
    let nw = key.len();
    let mut parity = C240;
    for (i, &w) in key.iter().enumerate() {
        ek[i] = w;
        parity ^= w;
    }
    ek[nw] = parity;
}

/// Build the extended tweak: t0, t1, t0 ^ t1.
fn extend_tweak(tweak: &[u64; 2]) -> [u64; 3] {
    [tweak[0], tweak[1], tweak[0] ^ tweak[1]]
}

// ---------------------------------------------------------------------------
// Per-variant constants (Skein 1.3, Table 4 + word permutations).
// rot[lane][round % 8]
// ---------------------------------------------------------------------------

const ROT_256: [[u32; 8]; 2] = [
    [14, 52, 23, 5, 25, 46, 58, 32],
    [16, 57, 40, 37, 33, 12, 22, 32],
];
const PERM_256: [usize; 4] = [0, 3, 2, 1];

const ROT_512: [[u32; 8]; 4] = [
    [46, 33, 17, 44, 39, 13, 25, 8],
    [36, 27, 49, 9, 30, 50, 29, 35],
    [19, 14, 36, 54, 34, 10, 39, 56],
    [37, 42, 39, 56, 24, 17, 43, 22],
];
const PERM_512: [usize; 8] = [2, 1, 4, 7, 6, 5, 0, 3];

const ROT_1024: [[u32; 8]; 8] = [
    [24, 38, 33, 5, 41, 16, 31, 9],
    [13, 19, 4, 20, 9, 34, 44, 48],
    [8, 10, 51, 48, 37, 56, 47, 35],
    [47, 55, 13, 41, 31, 51, 46, 52],
    [8, 49, 34, 47, 12, 4, 19, 23],
    [17, 18, 41, 28, 47, 53, 42, 31],
    [22, 23, 59, 16, 44, 42, 44, 37],
    [37, 52, 17, 25, 30, 41, 25, 20],
];
const PERM_1024: [usize; 16] = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1];

// ---------------------------------------------------------------------------
// Little-endian byte <-> u64 helpers.
// ---------------------------------------------------------------------------

fn bytes_to_words(bytes: &[u8], out: &mut [u64]) {
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
}

fn words_to_bytes(words: &[u64], out: &mut [u8]) {
    for (i, &w) in words.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
}

/// Increment a counter block by one, treating it as a big-endian integer and
/// wrapping on overflow.
///
/// The counter is derived from a public IV and block position, not from secret
/// material, so the carry-propagation branch here is not secret-dependent.
fn ctr_increment(block: &mut [u8]) {
    for byte in block.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API — one struct per block size.
// ---------------------------------------------------------------------------

// Each variant is a thin typed wrapper around the shared engine above. They are
// written out explicitly: the three differ only in their block size, word count,
// round count, and which constant tables they use. The cipher logic itself lives
// once, in the generic functions above.

/// Threefish with a 32-byte block and key (the 256-bit variant).
#[derive(Clone)]
pub struct Threefish256 {
    ek: [u64; 5],
    et: [u64; 3],
}

impl Threefish256 {
    /// Construct from a key and a 16-byte tweak (both little-endian).
    pub fn new(key: &[u8; 32], tweak: &[u8; 16]) -> Self {
        let mut kw = [0u64; 4];
        bytes_to_words(key, &mut kw);
        let mut tw = [0u64; 2];
        bytes_to_words(tweak, &mut tw);

        let mut ek = [0u64; 5];
        extend_key(&kw, &mut ek);
        Self {
            ek,
            et: extend_tweak(&tw),
        }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 32]) {
        let mut st = [0u64; 4];
        bytes_to_words(block, &mut st);
        encrypt(&mut st, &self.ek, &self.et, &ROT_256, &PERM_256, 72);
        words_to_bytes(&st, block);
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 32]) {
        let mut st = [0u64; 4];
        bytes_to_words(block, &mut st);
        decrypt(&mut st, &self.ek, &self.et, &ROT_256, &PERM_256, 72);
        words_to_bytes(&st, block);
    }

    /// Apply this cipher in counter (CTR) mode to `data` in place, processing any
    /// length.
    ///
    /// `iv` is the initial counter block. The whole block is treated as a
    /// big-endian integer and incremented by one for each successive block; the
    /// resulting keystream is xored into `data`. A trailing partial block uses
    /// only as many keystream bytes as it needs.
    ///
    /// CTR is symmetric: calling this again with the same key, tweak, and `iv`
    /// reverses it, so encryption and decryption are the same operation.
    ///
    /// SECURITY: never reuse a `(key, tweak, iv)` triple for two different
    /// messages. Doing so reuses the keystream and breaks confidentiality. CTR
    /// provides confidentiality only: it does not authenticate the data or detect
    /// tampering.
    pub fn ctr_apply(&self, iv: &[u8; 32], data: &mut [u8]) {
        let mut counter = *iv;
        let mut ks = [0u8; 32];
        for chunk in data.chunks_mut(32) {
            ks.copy_from_slice(&counter);
            self.encrypt_block(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= *k;
            }
            ctr_increment(&mut counter);
        }
    }
}

/// Threefish with a 64-byte block and key (the 512-bit variant).
#[derive(Clone)]
pub struct Threefish512 {
    ek: [u64; 9],
    et: [u64; 3],
}

impl Threefish512 {
    /// Construct from a key and a 16-byte tweak (both little-endian).
    pub fn new(key: &[u8; 64], tweak: &[u8; 16]) -> Self {
        let mut kw = [0u64; 8];
        bytes_to_words(key, &mut kw);
        let mut tw = [0u64; 2];
        bytes_to_words(tweak, &mut tw);

        let mut ek = [0u64; 9];
        extend_key(&kw, &mut ek);
        Self {
            ek,
            et: extend_tweak(&tw),
        }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 64]) {
        let mut st = [0u64; 8];
        bytes_to_words(block, &mut st);
        encrypt(&mut st, &self.ek, &self.et, &ROT_512, &PERM_512, 72);
        words_to_bytes(&st, block);
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 64]) {
        let mut st = [0u64; 8];
        bytes_to_words(block, &mut st);
        decrypt(&mut st, &self.ek, &self.et, &ROT_512, &PERM_512, 72);
        words_to_bytes(&st, block);
    }

    /// Apply this cipher in counter (CTR) mode to `data` in place. See
    /// [`Threefish256::ctr_apply`] for the full contract and security notes.
    pub fn ctr_apply(&self, iv: &[u8; 64], data: &mut [u8]) {
        let mut counter = *iv;
        let mut ks = [0u8; 64];
        for chunk in data.chunks_mut(64) {
            ks.copy_from_slice(&counter);
            self.encrypt_block(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= *k;
            }
            ctr_increment(&mut counter);
        }
    }
}

/// Threefish with a 128-byte block and key (the 1024-bit variant).
#[derive(Clone)]
pub struct Threefish1024 {
    ek: [u64; 17],
    et: [u64; 3],
}

impl Threefish1024 {
    /// Construct from a key and a 16-byte tweak (both little-endian).
    pub fn new(key: &[u8; 128], tweak: &[u8; 16]) -> Self {
        let mut kw = [0u64; 16];
        bytes_to_words(key, &mut kw);
        let mut tw = [0u64; 2];
        bytes_to_words(tweak, &mut tw);

        let mut ek = [0u64; 17];
        extend_key(&kw, &mut ek);
        Self {
            ek,
            et: extend_tweak(&tw),
        }
    }

    /// Encrypt one block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 128]) {
        let mut st = [0u64; 16];
        bytes_to_words(block, &mut st);
        encrypt(&mut st, &self.ek, &self.et, &ROT_1024, &PERM_1024, 80);
        words_to_bytes(&st, block);
    }

    /// Decrypt one block in place.
    pub fn decrypt_block(&self, block: &mut [u8; 128]) {
        let mut st = [0u64; 16];
        bytes_to_words(block, &mut st);
        decrypt(&mut st, &self.ek, &self.et, &ROT_1024, &PERM_1024, 80);
        words_to_bytes(&st, block);
    }

    /// Apply this cipher in counter (CTR) mode to `data` in place. See
    /// [`Threefish256::ctr_apply`] for the full contract and security notes.
    pub fn ctr_apply(&self, iv: &[u8; 128], data: &mut [u8]) {
        let mut counter = *iv;
        let mut ks = [0u8; 128];
        for chunk in data.chunks_mut(128) {
            ks.copy_from_slice(&counter);
            self.encrypt_block(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= *k;
            }
            ctr_increment(&mut counter);
        }
    }
}

#[cfg(test)]
mod tests;

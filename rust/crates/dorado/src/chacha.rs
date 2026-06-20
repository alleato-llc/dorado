//! ChaCha20 stream cipher (RFC 8439), implemented from scratch and verified
//! against the RFC's test vectors. Like Threefish it is a pure ARX design
//! (add / rotate / xor), so it has no lookup tables and a straightforward
//! implementation behaves in constant time on typical hardware.
//!
//! This is the cipher half of the ChaCha20-Poly1305 AEAD suite.

/// The four ChaCha constants: the ASCII of "expand 32-byte k", little-endian.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// One ChaCha quarter-round on four words of the state.
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function: produce one 64-byte keystream block for the key,
/// 32-bit block counter, and 96-bit nonce.
pub fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0..4].copy_from_slice(&CONSTANTS);
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    state[12] = counter;
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[13 + i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut working = state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, word) in working.iter().enumerate() {
        let sum = word.wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

/// Apply ChaCha20 to `data` in place, starting at `counter`. Encryption and
/// decryption are the same operation (xor with the keystream).
pub fn apply(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ks = block(key, counter.wrapping_add(i as u32), nonce);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
    }
}

#[cfg(test)]
mod tests;

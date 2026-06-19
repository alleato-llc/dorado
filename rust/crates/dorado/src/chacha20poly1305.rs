//! ChaCha20-Poly1305 AEAD (RFC 8439, section 2.8), built from the from-scratch
//! `chacha` and `poly1305` modules and verified against the RFC's test vector.
//!
//! This is the integrated style: the cipher mints a fresh one-time Poly1305 key
//! per message (from keystream block 0), encrypts the data from block 1 on, and
//! authenticates the associated data and ciphertext together.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{chacha, poly1305};

/// Length of the authentication tag.
pub const TAG_LEN: usize = 16;

/// Derive the one-time Poly1305 key for this message (keystream block 0).
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    chacha::block(key, 0, nonce)[..32].try_into().unwrap()
}

/// The Poly1305 input: aad || pad16 || ciphertext || pad16 || len(aad) ||
/// len(ciphertext), each length an 8-byte little-endian integer.
fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(aad.len() + ciphertext.len() + 48);
    m.extend_from_slice(aad);
    while m.len() % 16 != 0 {
        m.push(0);
    }
    m.extend_from_slice(ciphertext);
    while m.len() % 16 != 0 {
        m.push(0);
    }
    m.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    m.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    m
}

/// Constant-time equality for the tag comparison.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encrypt and authenticate: returns the ciphertext (same length as plaintext)
/// and a 16-byte tag.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let otk = poly_key(key, nonce);
    let mut ciphertext = plaintext.to_vec();
    chacha::apply(key, 1, nonce, &mut ciphertext);
    let tag = poly1305::mac(&otk, &mac_data(aad, &ciphertext));
    (ciphertext, tag)
}

/// Verify and decrypt. Returns the plaintext, or an error if the tag does not
/// match (wrong key, wrong AAD, or tampering).
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, String> {
    let otk = poly_key(key, nonce);
    let expected = poly1305::mac(&otk, &mac_data(aad, ciphertext));
    if !ct_eq(&expected, tag) {
        return Err("ChaCha20-Poly1305 authentication failed".into());
    }
    let mut plaintext = ciphertext.to_vec();
    chacha::apply(key, 1, nonce, &mut plaintext);
    Ok(plaintext)
}

#[cfg(test)]
mod tests;

//! ChaCha20-Poly1305 AEAD (RFC 8439, section 2.8), built from the from-scratch
//! `chacha` and `poly1305` modules and verified against the RFC's test vector.
//!
//! This is the integrated style: the cipher mints a fresh one-time Poly1305 key
//! per message (from keystream block 0), encrypts the data from block 1 on, and
//! authenticates the associated data and ciphertext together.
//!
//! The `*_in_place` functions are allocation-free: they transform the caller's
//! buffer and feed Poly1305 incrementally, so the AEAD works without a heap. The
//! `Vec`-returning [`seal`] / [`open`] are thin `alloc`-gated wrappers.

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::{chacha, poly1305};

/// Length of the authentication tag.
pub const TAG_LEN: usize = 16;

/// Returned by [`open_in_place`] when authentication fails. Allocation-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

/// Derive the one-time Poly1305 key for this message (keystream block 0).
fn poly_key(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    chacha::block(key, 0, nonce)[..32].try_into().unwrap()
}

/// Authenticate `aad` and `ciphertext` the RFC way: aad || pad16 || ciphertext
/// || pad16 || len(aad) || len(ciphertext), each length an 8-byte little-endian
/// integer. Fed to Poly1305 incrementally, so nothing is assembled in memory.
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let zeros = [0u8; 16];
    let mut p = poly1305::Poly1305::new(otk);
    p.update(aad);
    p.update(&zeros[..(16 - aad.len() % 16) % 16]);
    p.update(ciphertext);
    p.update(&zeros[..(16 - ciphertext.len() % 16) % 16]);
    p.update(&(aad.len() as u64).to_le_bytes());
    p.update(&(ciphertext.len() as u64).to_le_bytes());
    p.finalize()
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

/// Encrypt and authenticate in place: `buf` holds the plaintext on entry and the
/// ciphertext on return; the 16-byte tag is returned. Allocation-free.
pub fn seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    let otk = poly_key(key, nonce);
    chacha::apply(key, 1, nonce, buf);
    compute_tag(&otk, aad, buf)
}

/// Verify and decrypt in place: `buf` holds the ciphertext on entry and, on
/// success, the plaintext on return. Returns [`AuthError`] (and leaves `buf`
/// unchanged) if the tag does not match. Allocation-free.
pub fn open_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), AuthError> {
    let otk = poly_key(key, nonce);
    let expected = compute_tag(&otk, aad, buf);
    if !ct_eq(&expected, tag) {
        return Err(AuthError);
    }
    chacha::apply(key, 1, nonce, buf);
    Ok(())
}

/// Encrypt and authenticate: returns the ciphertext (same length as plaintext)
/// and a 16-byte tag. Convenience wrapper over [`seal_in_place`] (requires the
/// `alloc` feature).
#[cfg(feature = "alloc")]
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut buf = plaintext.to_vec();
    let tag = seal_in_place(key, nonce, aad, &mut buf);
    (buf, tag)
}

/// Verify and decrypt. Returns the plaintext, or an error if the tag does not
/// match (wrong key, wrong AAD, or tampering). Convenience wrapper over
/// [`open_in_place`] (requires the `alloc` feature).
#[cfg(feature = "alloc")]
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, String> {
    let mut buf = ciphertext.to_vec();
    open_in_place(key, nonce, aad, &mut buf, tag)
        .map_err(|_| String::from("ChaCha20-Poly1305 authentication failed"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests;

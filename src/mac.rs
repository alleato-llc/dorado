//! Message authentication for the password container (encrypt-then-MAC).
//!
//! After CTR encryption, an HMAC over the header and ciphertext is appended to
//! the file. On decryption the tag is verified in constant time before anything
//! is decrypted, so a wrong password or a tampered file is reported instead of
//! producing garbage. The MAC key is derived from the KDF alongside, but
//! separate from, the encryption key.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::format::MacId;

/// Length of the MAC key we derive from the KDF, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the authentication tag appended to the file, in bytes.
pub const TAG_LEN: usize = 32;

/// Compute the authentication tag over `signed`, which is the serialized header
/// followed by the ciphertext.
pub fn tag(mac: MacId, mac_key: &[u8], signed: &[u8]) -> Vec<u8> {
    match mac {
        MacId::HmacSha256 => {
            let mut h =
                <Hmac<Sha256>>::new_from_slice(mac_key).expect("HMAC accepts a key of any length");
            h.update(signed);
            h.finalize().into_bytes().to_vec()
        }
    }
}

/// Verify `tag` against `signed` in constant time. An error means the tag did
/// not match, i.e. a wrong password or a corrupted or tampered file.
pub fn verify(mac: MacId, mac_key: &[u8], signed: &[u8], tag: &[u8]) -> Result<(), String> {
    match mac {
        MacId::HmacSha256 => {
            let mut h =
                <Hmac<Sha256>>::new_from_slice(mac_key).expect("HMAC accepts a key of any length");
            h.update(signed);
            h.verify_slice(tag)
                .map_err(|_| "authentication failed: wrong password or corrupted file".to_string())
        }
    }
}

#[cfg(test)]
mod tests;

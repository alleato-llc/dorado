//! Message authentication for the password container (encrypt-then-MAC).
//!
//! After CTR encryption, a MAC over the header and ciphertext is appended to the
//! file. On decryption the tag is verified in constant time before anything is
//! decrypted, so a wrong password or a tampered file is reported instead of
//! producing garbage. The MAC key is derived from the KDF alongside, but separate
//! from, the encryption key.
//!
//! Three MACs are available, all producing a 32-byte tag from the 32-byte key:
//! Skein-512 (the default; Threefish-native), HMAC-SHA256, and BLAKE3 keyed.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::format::MacId;

/// Length of the MAC key we derive from the KDF, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the authentication tag appended to the file, in bytes.
pub const TAG_LEN: usize = 32;

/// Compute the authentication tag over `signed`, which is the serialized header
/// followed by the ciphertext.
pub fn tag(mac: MacId, mac_key: &[u8], signed: &[u8]) -> Vec<u8> {
    match mac {
        MacId::Skein512 => dorado::skein::mac(mac_key, TAG_LEN, signed),
        MacId::HmacSha256 => {
            let mut h =
                <Hmac<Sha256>>::new_from_slice(mac_key).expect("HMAC accepts a key of any length");
            h.update(signed);
            h.finalize().into_bytes().to_vec()
        }
        MacId::Blake3 => {
            let key: [u8; 32] = mac_key.try_into().expect("MAC key is 32 bytes");
            dorado::blake3::keyed_mac(&key, TAG_LEN, signed)
        }
    }
}

/// Verify `received` against `signed` in constant time. An error means the tag
/// did not match, i.e. a wrong password or a corrupted or tampered file.
pub fn verify(mac: MacId, mac_key: &[u8], signed: &[u8], received: &[u8]) -> Result<()> {
    let expected = tag(mac, mac_key, signed);
    if ct_eq(&expected, received) {
        Ok(())
    } else {
        Err(Error::AuthFailed)
    }
}

/// Constant-time byte-slice equality.
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

#[cfg(test)]
mod tests;

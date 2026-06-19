//! RustCrypto `cipher` trait implementations for the Threefish variants, behind
//! the optional `cipher` feature. These let dorado's cipher plug into the
//! RustCrypto ecosystem (generic block modes, AEADs, and so on).
//!
//! `KeyInit` constructs the cipher with an all-zero tweak, matching the
//! convention of the RustCrypto `threefish` crate. For a non-zero tweak, use the
//! inherent `Threefish*::new(key, tweak)` constructor directly.

use cipher::consts::{U128, U32, U64};
use cipher::{BlockCipher, Key, KeyInit, KeySizeUser};

use crate::{Threefish1024, Threefish256, Threefish512};

// Each variant's trait glue is identical apart from its sizes, so a local macro
// keeps the boilerplate honest. `impl_simple_block_encdec!` (from `cipher`)
// provides `BlockSizeUser`, `BlockEncrypt`, and `BlockDecrypt`; we add the key
// traits and the `BlockCipher` marker.
macro_rules! impl_cipher_traits {
    ($variant:ident, $size:ty, $n:literal) => {
        impl KeySizeUser for $variant {
            type KeySize = $size;
        }

        impl KeyInit for $variant {
            fn new(key: &Key<Self>) -> Self {
                // Inherent `new(key, tweak)`; the tweak defaults to all-zero.
                <$variant>::new(key.as_slice().try_into().unwrap(), &[0u8; 16])
            }
        }

        impl BlockCipher for $variant {}

        cipher::impl_simple_block_encdec!(
            $variant, $size, state, block,
            encrypt: {
                let mut buf = [0u8; $n];
                buf.copy_from_slice(block.get_in());
                state.encrypt_block(&mut buf);
                block.get_out().copy_from_slice(&buf);
            }
            decrypt: {
                let mut buf = [0u8; $n];
                buf.copy_from_slice(block.get_in());
                state.decrypt_block(&mut buf);
                block.get_out().copy_from_slice(&buf);
            }
        );
    };
}

impl_cipher_traits!(Threefish256, U32, 32);
impl_cipher_traits!(Threefish512, U64, 64);
impl_cipher_traits!(Threefish1024, U128, 128);

#[cfg(test)]
mod tests;

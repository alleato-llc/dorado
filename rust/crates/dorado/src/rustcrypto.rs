//! RustCrypto trait implementations for ecosystem interop, behind the optional
//! `cipher` (block cipher) and `digest` (hashes) features.

#[cfg(feature = "cipher")]
mod cipher_impls {
    //! `cipher` block-cipher traits for the Threefish variants.
    //!
    //! `KeyInit` constructs with an all-zero tweak, matching the RustCrypto
    //! `threefish` crate; for a non-zero tweak use the inherent
    //! `Threefish*::new(key, tweak)`.

    use cipher::consts::{U128, U32, U64};
    use cipher::{BlockCipher, Key, KeyInit, KeySizeUser};

    use crate::{Threefish1024, Threefish256, Threefish512};

    // The three variants' glue is identical apart from sizes, so a local macro
    // keeps the boilerplate honest. `impl_simple_block_encdec!` provides
    // `BlockSizeUser`, `BlockEncrypt`, and `BlockDecrypt`.
    macro_rules! impl_cipher_traits {
        ($variant:ident, $size:ty, $n:literal) => {
            impl KeySizeUser for $variant {
                type KeySize = $size;
            }

            impl KeyInit for $variant {
                fn new(key: &Key<Self>) -> Self {
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
}

#[cfg(feature = "digest")]
pub mod digest_impls {
    //! `digest` hash traits. BLAKE3 is exposed as its standard 32-byte `Digest`
    //! (the inherent `blake3::Hasher` still gives arbitrary-length XOF output).
    //! Skein's output length is fixed at construction, so it gets one fixed-size
    //! wrapper type per common output length.

    use digest::consts::{U32, U64};
    use digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update};

    use crate::{blake3, skein};

    // --- BLAKE3 as a 32-byte Digest ---

    impl HashMarker for blake3::Hasher {}

    impl OutputSizeUser for blake3::Hasher {
        type OutputSize = U32;
    }

    impl Update for blake3::Hasher {
        fn update(&mut self, data: &[u8]) {
            blake3::Hasher::update(self, data);
        }
    }

    impl FixedOutput for blake3::Hasher {
        fn finalize_into(self, out: &mut Output<Self>) {
            blake3::Hasher::finalize_into(&self, out);
        }
    }

    // --- Skein-512 fixed-output Digest wrappers ---

    macro_rules! skein_digest {
        ($name:ident, $size:ty, $bytes:literal, $doc:literal) => {
            #[doc = $doc]
            pub struct $name(skein::Skein512);

            impl Default for $name {
                fn default() -> Self {
                    $name(skein::Skein512::new($bytes))
                }
            }

            impl HashMarker for $name {}

            impl OutputSizeUser for $name {
                type OutputSize = $size;
            }

            impl Update for $name {
                fn update(&mut self, data: &[u8]) {
                    self.0.update(data);
                }
            }

            impl FixedOutput for $name {
                fn finalize_into(self, out: &mut Output<Self>) {
                    self.0.finalize_into(out);
                }
            }
        };
    }

    skein_digest!(
        Skein512_256,
        U32,
        32,
        "Skein-512 with 256-bit output, as a RustCrypto `Digest`."
    );
    skein_digest!(
        Skein512_512,
        U64,
        64,
        "Skein-512 with 512-bit output, as a RustCrypto `Digest`."
    );
}

#[cfg(test)]
mod tests;

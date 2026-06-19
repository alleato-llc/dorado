#[cfg(feature = "cipher")]
mod cipher_traits {
    use cipher::generic_array::GenericArray;
    use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

    use crate::{Threefish1024, Threefish256, Threefish512};

    // The inherent `encrypt_block`/`decrypt_block` shadow the trait methods in
    // method-call syntax, so these call the trait via UFCS. Generic RustCrypto
    // code (block modes, AEADs) reaches the trait through its bound.
    #[test]
    fn trait_impls_match_the_native_api_with_a_zero_tweak() {
        // Threefish-256.
        let key = [0x11u8; 32];
        let native = Threefish256::new(&key, &[0u8; 16]);
        let rc = <Threefish256 as KeyInit>::new(GenericArray::from_slice(&key));

        let mut block = GenericArray::clone_from_slice(&[0x22u8; 32]);
        let mut native_block = [0x22u8; 32];
        BlockEncrypt::encrypt_block(&rc, &mut block);
        native.encrypt_block(&mut native_block);
        assert_eq!(block.as_slice(), &native_block[..], "256 encrypt");

        BlockDecrypt::decrypt_block(&rc, &mut block);
        assert_eq!(block.as_slice(), &[0x22u8; 32][..], "256 round-trip");

        // Threefish-512.
        let rc = <Threefish512 as KeyInit>::new(GenericArray::from_slice(&[0x33u8; 64]));
        let native = Threefish512::new(&[0x33u8; 64], &[0u8; 16]);
        let mut block = GenericArray::clone_from_slice(&[0x44u8; 64]);
        let mut native_block = [0x44u8; 64];
        BlockEncrypt::encrypt_block(&rc, &mut block);
        native.encrypt_block(&mut native_block);
        assert_eq!(block.as_slice(), &native_block[..], "512 encrypt");

        // Threefish-1024.
        let rc = <Threefish1024 as KeyInit>::new(GenericArray::from_slice(&[0x55u8; 128]));
        let mut block = GenericArray::clone_from_slice(&[0x66u8; 128]);
        BlockEncrypt::encrypt_block(&rc, &mut block);
        BlockDecrypt::decrypt_block(&rc, &mut block);
        assert_eq!(block.as_slice(), &[0x66u8; 128][..], "1024 round-trip");
    }
}

#[cfg(feature = "digest")]
mod digest_traits {
    use digest::Digest;

    use crate::rustcrypto::digest_impls::{Skein512_256, Skein512_512};
    use crate::{blake3, skein};

    #[test]
    fn blake3_digest_matches_the_native_hasher() {
        let msg = b"digest trait over the BLAKE3 hasher";
        let via_digest = blake3::Hasher::digest(msg);

        let mut want = [0u8; 32];
        blake3::hash_into(&mut want, msg);
        assert_eq!(via_digest.as_slice(), &want[..]);

        // The incremental Digest API agrees with the one-shot.
        let mut h = blake3::Hasher::new();
        Digest::update(&mut h, b"digest trait over ");
        Digest::update(&mut h, b"the BLAKE3 hasher");
        assert_eq!(h.finalize().as_slice(), &want[..]);
    }

    #[test]
    fn skein_digest_wrappers_match_the_native_hash() {
        let msg = b"digest trait over Skein-512";

        let mut want256 = [0u8; 32];
        skein::hash_into(&mut want256, msg);
        assert_eq!(Skein512_256::digest(msg).as_slice(), &want256[..]);

        let mut want512 = [0u8; 64];
        skein::hash_into(&mut want512, msg);
        assert_eq!(Skein512_512::digest(msg).as_slice(), &want512[..]);
    }
}

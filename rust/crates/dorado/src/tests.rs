//! Unit tests for the cipher, kept separate from the implementation in
//! `lib.rs`. Declared there as `#[cfg(test)] mod tests;`.

mod known_answer {
    //! Official known-answer vectors (Crypto++ threefish.txt), with non-trivial
    //! key, tweak, and plaintext for each block size.
    use crate::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const TWEAK: &str = "000102030405060708090A0B0C0D0E0F";

    #[test]
    fn t256_official() {
        let key = unhex("101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F");
        let tweak = unhex(TWEAK);
        let pt = unhex("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0");
        let ct = unhex("E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF");

        let c = Threefish256::new(&key[..].try_into().unwrap(), &tweak[..].try_into().unwrap());
        let mut b: [u8; 32] = pt[..].try_into().unwrap();
        c.encrypt_block(&mut b);
        assert_eq!(&b[..], &ct[..], "256 encrypt");
        c.decrypt_block(&mut b);
        assert_eq!(&b[..], &pt[..], "256 decrypt");
    }

    #[test]
    fn t512_official() {
        let key = unhex(
            "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F\
             303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F",
        );
        let tweak = unhex(TWEAK);
        let pt = unhex(
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0\
             DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
        );
        let ct = unhex(
            "E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779\
             272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D",
        );

        let c = Threefish512::new(&key[..].try_into().unwrap(), &tweak[..].try_into().unwrap());
        let mut b: [u8; 64] = pt[..].try_into().unwrap();
        c.encrypt_block(&mut b);
        assert_eq!(&b[..], &ct[..], "512 encrypt");
        c.decrypt_block(&mut b);
        assert_eq!(&b[..], &pt[..], "512 decrypt");
    }

    #[test]
    fn t1024_official() {
        let key = unhex(
            "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F\
             303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F\
             505152535455565758595A5B5C5D5E5F6061626364656667 68696A6B6C6D6E6F\
             707172737475767778797A7B7C7D7E7F8081828384858687 88898A8B8C8D8E8F",
        );
        let tweak = unhex(TWEAK);
        let pt = unhex(
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0\
             DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0\
             BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0\
             9F9E9D9C9B9A99989796959493929190 8F8E8D8C8B8A89888786858483828180",
        );
        let ct = unhex(
            "A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C\
             94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD\
             8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8\
             3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE",
        );

        let c = Threefish1024::new(&key[..].try_into().unwrap(), &tweak[..].try_into().unwrap());
        let mut b: [u8; 128] = pt[..].try_into().unwrap();
        c.encrypt_block(&mut b);
        assert_eq!(&b[..], &ct[..], "1024 encrypt");
        c.decrypt_block(&mut b);
        assert_eq!(&b[..], &pt[..], "1024 decrypt");
    }
}

mod ctr {
    //! CTR mode has no official test vectors (it is not part of the Threefish
    //! or Skein specification), so these tests anchor it to the block cipher,
    //! which is itself verified against official vectors and the RustCrypto
    //! reference. We check that the keystream equals the block cipher applied to
    //! successive counter values, and that the transform round-trips at lengths
    //! that are not block multiples.
    use crate::*;

    #[test]
    fn counter_increment_carries() {
        let mut b = [0x00, 0xff, 0xff];
        ctr_increment(&mut b);
        assert_eq!(b, [0x01, 0x00, 0x00]);

        let mut all = [0xff, 0xff];
        ctr_increment(&mut all);
        assert_eq!(all, [0x00, 0x00], "wraps on overflow");
    }

    #[test]
    fn keystream_matches_block_cipher() {
        // Xoring against zeros yields the raw keystream, which must equal the
        // block cipher applied to counter, counter+1, counter+2.
        let key = [0x11u8; 32];
        let tweak = [0x22u8; 16];
        let iv = [0u8; 32];
        let c = Threefish256::new(&key, &tweak);

        let mut data = [0u8; 96]; // three full blocks
        c.ctr_apply(&iv, &mut data);

        let mut counter = iv;
        for block in data.chunks_exact(32) {
            let mut expected = counter;
            c.encrypt_block(&mut expected);
            assert_eq!(block, &expected[..], "keystream block mismatch");
            ctr_increment(&mut counter);
        }
    }

    #[test]
    fn roundtrip_partial_block() {
        let key = [0x33u8; 64];
        let tweak = [0x44u8; 16];
        let iv = [0x55u8; 64];
        let c = Threefish512::new(&key, &tweak);

        // Length deliberately not a multiple of the 64-byte block.
        let original: Vec<u8> = (0u8..100).collect();
        let mut data = original.clone();

        c.ctr_apply(&iv, &mut data);
        assert_ne!(data, original, "ciphertext should differ from plaintext");
        c.ctr_apply(&iv, &mut data);
        assert_eq!(data, original, "CTR did not round-trip");
    }

    #[test]
    fn empty_input_is_noop() {
        let c = Threefish1024::new(&[0x66u8; 128], &[0x77u8; 16]);
        let mut data: [u8; 0] = [];
        c.ctr_apply(&[0u8; 128], &mut data);
        assert_eq!(data, []);
    }
}

mod known_answer_zero {
    //! Additional official vectors from the Crypto++ `TestVectors/threefish.txt`
    //! file: the all-zero key, tweak, and plaintext case for each block size.
    //! These complement the incrementing-pattern vectors above.
    //!
    //! Crypto++ prints each 64-bit word as big-endian hex. Threefish treats its
    //! state as little-endian words, so `words` parses each whitespace-separated
    //! group as a `u64` and emits it little-endian, matching the byte-oriented
    //! public API.
    use crate::*;

    fn words(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .flat_map(|w| u64::from_str_radix(w, 16).expect("hex word").to_le_bytes())
            .collect()
    }

    macro_rules! kat {
        ($name:ident, $ty:ty, $bytes:expr, $key:expr, $tweak:expr, $pt:expr, $ct:expr) => {
            #[test]
            fn $name() {
                let key = words($key);
                let tweak = words($tweak);
                let pt = words($pt);
                let ct = words($ct);
                let c = <$ty>::new(key[..].try_into().unwrap(), tweak[..].try_into().unwrap());
                let mut b: [u8; $bytes] = pt[..].try_into().unwrap();
                c.encrypt_block(&mut b);
                assert_eq!(&b[..], &ct[..], "encrypt");
                c.decrypt_block(&mut b);
                assert_eq!(&b[..], &pt[..], "decrypt");
            }
        };
    }

    const ZERO_TWEAK: &str = "0000000000000000 0000000000000000";

    kat!(
        t256_zero,
        Threefish256,
        32,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        ZERO_TWEAK,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        "94EEEA8B1F2ADA84 ADF103313EAE6670 952419A1F4B16D53 D83F13E63C9F6B11"
    );

    kat!(
        t512_zero,
        Threefish512,
        64,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        ZERO_TWEAK,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        "BC2560EFC6BBA2B1 E3361F162238EB40 FB8631EE0ABBD175 7B9479D4C5479ED1 \
         CFF0356E58F8C27B B1B7B08430F0E7F7 E9A380A56139ABF1 BE7B6D4AA11EB47E"
    );

    kat!(
        t1024_zero,
        Threefish1024,
        128,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        ZERO_TWEAK,
        "0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000 \
         0000000000000000 0000000000000000 0000000000000000 0000000000000000",
        "04B3053D0A3D5CF0 0136E0D1C7DD85F7 067B212F6EA78A5C 0DA9C10B4C54E1C6 \
         0F4EC27394CBACF0 32437F0568EA4FD5 CFF56D1D7654B49C A2D5FB14369B2E7B \
         540306B460472E0B 71C18254BCEA820D C36B4068BEAF32C8 FA4329597A360095 \
         C4A36C28434A5B9A D54331444B1046CF DF11834830B2A460 1E39E8DFE1F7EE4F"
    );
}

#[cfg(feature = "zeroize")]
mod zeroize_feature {
    //! With the `zeroize` feature, each cipher gains a `Drop` that wipes its key
    //! schedule. Reading the freed bytes back would need `unsafe` (forbidden
    //! here), so we assert the drop glue exists, which is what runs the wipe.
    use crate::{Threefish1024, Threefish256, Threefish512};

    #[test]
    fn ciphers_have_drop_glue() {
        assert!(std::mem::needs_drop::<Threefish256>());
        assert!(std::mem::needs_drop::<Threefish512>());
        assert!(std::mem::needs_drop::<Threefish1024>());
    }

    #[test]
    fn round_trip_still_works_with_zeroize() {
        let cipher = Threefish256::new(&[0x11; 32], &[0x22; 16]);
        let mut block = [0x33u8; 32];
        cipher.encrypt_block(&mut block);
        cipher.decrypt_block(&mut block);
        assert_eq!(block, [0x33u8; 32]);
    }
}

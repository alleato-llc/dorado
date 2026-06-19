//! Differential tests: my implementation vs. the RustCrypto `threefish` crate.
//! Both are driven as byte -> byte transforms over the same random inputs.

use rand::RngCore;

macro_rules! diff_test {
    ($test:ident, $mine:ty, $theirs:ty, $bytes:expr, $nw:expr) => {
        #[test]
        fn $test() {
            let mut rng = rand::thread_rng();
            for _ in 0..5000 {
                let mut key = [0u8; $bytes];
                let mut tweak = [0u8; 16];
                let mut pt = [0u8; $bytes];
                rng.fill_bytes(&mut key);
                rng.fill_bytes(&mut tweak);
                rng.fill_bytes(&mut pt);

                // My implementation (bytes in, bytes out).
                let mine = <$mine>::new(&key, &tweak);
                let mut mine_ct = pt;
                mine.encrypt_block(&mut mine_ct);

                // Reference implementation, fed identical little-endian words.
                let theirs = <$theirs>::new_with_tweak(&key, &tweak);
                let mut words = [0u64; $nw];
                for (w, c) in words.iter_mut().zip(pt.chunks_exact(8)) {
                    *w = u64::from_le_bytes(c.try_into().unwrap());
                }
                theirs.encrypt_block_u64(&mut words);
                let mut theirs_ct = [0u8; $bytes];
                for (i, w) in words.iter().enumerate() {
                    theirs_ct[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
                }

                assert_eq!(mine_ct, theirs_ct, "ciphertext mismatch vs reference");

                // My decrypt must invert my encrypt.
                let mut back = mine_ct;
                mine.decrypt_block(&mut back);
                assert_eq!(back, pt, "decrypt did not recover plaintext");
            }
        }
    };
}

diff_test!(
    diff_256,
    dorado::Threefish256,
    threefish::Threefish256,
    32,
    4
);
diff_test!(
    diff_512,
    dorado::Threefish512,
    threefish::Threefish512,
    64,
    8
);
diff_test!(
    diff_1024,
    dorado::Threefish1024,
    threefish::Threefish1024,
    128,
    16
);

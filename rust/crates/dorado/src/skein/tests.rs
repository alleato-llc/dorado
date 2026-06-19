use super::*;
use digest::Digest;
use rand::RngCore;

// Differential test against the RustCrypto `skein` crate over random inputs,
// at both 256- and 512-bit output lengths. If our from-scratch UBI/config/output
// is correct, the digests match the reference exactly.
#[test]
fn matches_rustcrypto_skein512() {
    let mut rng = rand::thread_rng();
    for _ in 0..300 {
        let len = (rng.next_u32() % 300) as usize;
        let mut msg = vec![0u8; len];
        rng.fill_bytes(&mut msg);

        let mine = hash(64, &msg);
        let theirs = skein::Skein512::<digest::consts::U64>::digest(&msg);
        assert_eq!(
            &mine[..],
            &theirs[..],
            "Skein-512-512 mismatch at len {len}"
        );

        let mine = hash(32, &msg);
        let theirs = skein::Skein512::<digest::consts::U32>::digest(&msg);
        assert_eq!(
            &mine[..],
            &theirs[..],
            "Skein-512-256 mismatch at len {len}"
        );
    }
}

#[test]
fn mac_is_deterministic_and_key_sensitive() {
    let key = [0x11u8; 32];
    let msg = b"authenticate me";
    let a = mac(&key, 32, msg);
    let b = mac(&key, 32, msg);
    assert_eq!(a, b, "same inputs must give the same tag");
    assert_eq!(a.len(), 32);

    let other = mac(&[0x22u8; 32], 32, msg);
    assert_ne!(a, other, "a different key must give a different tag");

    let tampered = mac(&key, 32, b"authenticate ne");
    assert_ne!(a, tampered, "a different message must give a different tag");
}

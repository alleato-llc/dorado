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

#[test]
fn incremental_matches_one_shot_at_awkward_splits() {
    let msg: Vec<u8> = (0..500u16).map(|i| i as u8).collect();
    let want = hash(32, &msg);
    // Feeding the same bytes in any chunking, including splits across the 64-byte
    // UBI block boundary and a partial final block, must give the same digest.
    for step in [1usize, 7, 63, 64, 65, 200] {
        let mut h = Skein512::new(32);
        for chunk in msg.chunks(step) {
            h.update(chunk);
        }
        let mut out = [0u8; 32];
        h.finalize_into(&mut out);
        assert_eq!(&out[..], &want[..], "mismatch at step {step}");
    }

    // The keyed (MAC) streaming path must match too.
    let key = [0x9cu8; 32];
    let want = mac(&key, 32, &msg);
    let mut h = Skein512::new_mac(&key, 32);
    for chunk in msg.chunks(17) {
        h.update(chunk);
    }
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    assert_eq!(&out[..], &want[..], "keyed streaming mismatch");
}

#[test]
fn into_forms_match_the_allocating_forms() {
    // hash_into / mac_into are the allocation-free core; the Vec-returning
    // hash / mac are thin wrappers, so they must agree byte for byte.
    for len in [16usize, 32, 64, 100] {
        let msg = b"the same message at several output lengths";
        let mut buf = vec![0u8; len];
        hash_into(&mut buf, msg);
        assert_eq!(buf, hash(len, msg), "hash_into mismatch at {len}");

        let key = [0x5au8; 32];
        let mut tag = vec![0u8; len];
        mac_into(&mut tag, &key, msg);
        assert_eq!(tag, mac(&key, len, msg), "mac_into mismatch at {len}");
    }
}

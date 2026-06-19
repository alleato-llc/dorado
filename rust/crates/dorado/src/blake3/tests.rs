use super::*;
use rand::RngCore;

// Differential test against the `blake3` crate over random inputs spanning many
// chunks (so the Merkle tree, the power-of-two split, and parent nodes are all
// exercised), at the default 32-byte output, an extended XOF length, and keyed.
#[test]
fn matches_blake3_crate() {
    let mut rng = rand::thread_rng();
    // Lengths around chunk and tree boundaries (including deeper trees, to
    // exercise the streaming chunk-stack merges) plus random sizes.
    let mut lengths: Vec<usize> = vec![
        0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 4096, 6000, 8192, 8193, 16384, 16385,
        32768, 32769, 50000,
    ];
    for _ in 0..50 {
        lengths.push((rng.next_u32() % 40000) as usize);
    }

    for len in lengths {
        let mut msg = vec![0u8; len];
        rng.fill_bytes(&mut msg);

        // Default 32-byte hash.
        let mine = hash(32, &msg);
        let theirs = blake3::hash(&msg);
        assert_eq!(&mine[..], theirs.as_bytes(), "hash mismatch at len {len}");

        // Extended output (XOF).
        let mine = hash(131, &msg);
        let mut buf = [0u8; 131];
        blake3::Hasher::new()
            .update(&msg)
            .finalize_xof()
            .fill(&mut buf);
        assert_eq!(&mine[..], &buf[..], "xof mismatch at len {len}");

        // Keyed MAC.
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let mine = keyed_mac(&key, 32, &msg);
        let theirs = blake3::keyed_hash(&key, &msg);
        assert_eq!(&mine[..], theirs.as_bytes(), "keyed mismatch at len {len}");
    }
}

#[test]
fn incremental_matches_one_shot_at_awkward_splits() {
    let mut rng = rand::thread_rng();
    // Multi-chunk input so the chunk-stack merging runs during streaming.
    let mut msg = vec![0u8; 20_000];
    rng.fill_bytes(&mut msg);
    let want = hash(32, &msg);

    // Feeding the same bytes in any chunking, including splits across the
    // 64-byte block and 1024-byte chunk boundaries, must give the same digest.
    for step in [1usize, 63, 64, 100, 1023, 1024, 1025, 4096] {
        let mut h = Hasher::new();
        for chunk in msg.chunks(step) {
            h.update(chunk);
        }
        let mut out = [0u8; 32];
        h.finalize_into(&mut out);
        assert_eq!(&out[..], &want[..], "mismatch at step {step}");
    }

    // The keyed streaming path must match too.
    let key = [0x71u8; 32];
    let want = keyed_mac(&key, 32, &msg);
    let mut h = Hasher::new_keyed(&key);
    for chunk in msg.chunks(777) {
        h.update(chunk);
    }
    let mut out = [0u8; 32];
    h.finalize_into(&mut out);
    assert_eq!(&out[..], &want[..], "keyed streaming mismatch");
}

#[test]
fn into_forms_match_the_allocating_forms() {
    // hash_into / keyed_mac_into are the allocation-free core; the Vec-returning
    // wrappers must agree with them byte for byte, including XOF lengths.
    for len in [16usize, 32, 73, 128] {
        let input = b"merkle tree input across a few output lengths";
        let mut buf = vec![0u8; len];
        hash_into(&mut buf, input);
        assert_eq!(buf, hash(len, input), "hash_into mismatch at {len}");

        let key = [0x42u8; 32];
        let mut tag = vec![0u8; len];
        keyed_mac_into(&mut tag, &key, input);
        assert_eq!(
            tag,
            keyed_mac(&key, len, input),
            "keyed_mac_into mismatch at {len}"
        );
    }
}

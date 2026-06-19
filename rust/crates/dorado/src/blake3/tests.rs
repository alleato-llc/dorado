use super::*;
use rand::RngCore;

// Differential test against the `blake3` crate over random inputs spanning many
// chunks (so the Merkle tree, the power-of-two split, and parent nodes are all
// exercised), at the default 32-byte output, an extended XOF length, and keyed.
#[test]
fn matches_blake3_crate() {
    let mut rng = rand::thread_rng();
    // Lengths around chunk and tree boundaries plus random sizes.
    let mut lengths: Vec<usize> = vec![0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 4096, 6000];
    for _ in 0..50 {
        lengths.push((rng.next_u32() % 8000) as usize);
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

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc8439_tag() {
    // RFC 8439, section 2.5.2.
    let key: [u8; 32] = unhex("85d6be7857556d337f4452fe42d506a801038 08afb0db2fd4abff6af4149f51b")
        [..]
        .try_into()
        .unwrap();
    let msg = b"Cryptographic Forum Research Group";
    let expected = unhex("a8061dc1305136c6c22b8baf0c0127a9");

    let tag = mac(&key, msg);
    assert_eq!(&tag[..], &expected[..], "Poly1305 tag mismatch");
}

#[test]
fn empty_and_partial_blocks() {
    // Stable across re-runs and handles non-block-multiple lengths without panic.
    let key = [0x11u8; 32];
    let a = mac(&key, b"");
    let b = mac(&key, b"");
    assert_eq!(a, b);

    let _ = mac(&key, b"x"); // 1 byte
    let _ = mac(&key, &[0u8; 16]); // exactly one block
    let _ = mac(&key, &[0u8; 17]); // one block + 1
    let _ = mac(&key, &[0u8; 64]); // several blocks
}

#[test]
fn incremental_matches_one_shot_at_awkward_splits() {
    let key = [0x24u8; 32];
    let msg: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
    let want = mac(&key, &msg);

    // Feeding the same bytes in any chunking must give the same tag, including
    // splits that land mid-block and a leftover partial final block.
    for step in [1usize, 3, 7, 16, 31, 64] {
        let mut p = Poly1305::new(&key);
        for chunk in msg.chunks(step) {
            p.update(chunk);
        }
        assert_eq!(p.finalize(), want, "mismatch at step {step}");
    }
}

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc8439_aead() {
    // RFC 8439, section 2.8.2.
    let key: [u8; 32] =
        unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")[..]
            .try_into()
            .unwrap();
    let nonce: [u8; 12] = unhex("070000004041424344454647")[..].try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ct = unhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116",
    );
    let expected_tag = unhex("1ae10b594f09e26a7e902ecbd0600691");

    let (ct, tag) = seal(&key, &nonce, &aad, plaintext);
    assert_eq!(ct, expected_ct, "ciphertext mismatch");
    assert_eq!(&tag[..], &expected_tag[..], "tag mismatch");

    let pt = open(&key, &nonce, &aad, &ct, &tag).unwrap();
    assert_eq!(&pt[..], &plaintext[..], "round-trip failed");
}

#[test]
fn rejects_tampering_and_wrong_aad() {
    let key = [0x11u8; 32];
    let nonce = [0x22u8; 12];
    let aad = b"context";
    let (ct, tag) = seal(&key, &nonce, aad, b"secret message");

    open(&key, &nonce, aad, &ct, &tag).unwrap();

    // Flipped ciphertext byte.
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(open(&key, &nonce, aad, &bad, &tag).is_err());

    // Wrong associated data.
    assert!(open(&key, &nonce, b"other", &ct, &tag).is_err());

    // Flipped tag byte.
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(open(&key, &nonce, aad, &ct, &bad_tag).is_err());
}

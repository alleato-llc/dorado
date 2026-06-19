use super::*;

#[test]
fn verify_accepts_valid_tag() {
    let key = [0x11u8; KEY_LEN];
    let data = b"header and ciphertext";
    let t = tag(MacId::HmacSha256, &key, data);
    assert_eq!(t.len(), TAG_LEN);
    verify(MacId::HmacSha256, &key, data, &t).unwrap();
}

#[test]
fn verify_rejects_tampering_and_wrong_key() {
    let key = [0x11u8; KEY_LEN];
    let data = b"header and ciphertext";
    let t = tag(MacId::HmacSha256, &key, data);

    // Flipping a single bit of the data must fail.
    let mut tampered = data.to_vec();
    tampered[0] ^= 1;
    assert!(verify(MacId::HmacSha256, &key, &tampered, &t).is_err());

    // A different key models a wrong password.
    let wrong = [0x22u8; KEY_LEN];
    assert!(verify(MacId::HmacSha256, &wrong, data, &t).is_err());
}

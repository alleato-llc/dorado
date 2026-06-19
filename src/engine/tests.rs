use super::*;
use crate::kdf::{KdfParams, PrfId};

#[test]
fn advance_counter_adds_and_carries() {
    let mut c = [0u8, 0, 0, 0];
    advance_counter(&mut c, 1);
    assert_eq!(c, [0, 0, 0, 1]);

    let mut c = [0u8, 0, 0, 0xff];
    advance_counter(&mut c, 1);
    assert_eq!(c, [0, 0, 1, 0], "carry across a byte boundary");

    let mut c = [0u8, 0, 0, 0];
    advance_counter(&mut c, 0x0102);
    assert_eq!(c, [0, 0, 1, 2], "multi-byte addend");

    let mut c = [0xffu8, 0xff, 0xff, 0xff];
    advance_counter(&mut c, 1);
    assert_eq!(c, [0, 0, 0, 0], "wraps on overflow");
}

// PBKDF2 with a low round count keeps these fast.
fn fast_opts() -> PasswordOptions {
    PasswordOptions {
        kdf: KdfParams::Pbkdf2 {
            rounds: 1000,
            prf: PrfId::HmacSha256,
        },
        ..Default::default()
    }
}

#[test]
fn password_round_trip_and_rejects_tampering() {
    let opts = fast_opts();
    let pw = b"hunter2";
    let pt = b"a message that spans more than nothing";

    let ct = encrypt_password_bytes(pw, &opts, pt).unwrap();
    assert_ne!(&ct[..], &pt[..]);

    let back = decrypt_password_bytes(pw, &ct).unwrap();
    assert_eq!(&back[..], &pt[..]);

    assert!(
        decrypt_password_bytes(b"wrong", &ct).is_err(),
        "wrong password must fail"
    );

    let mut tampered = ct.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        decrypt_password_bytes(pw, &tampered).is_err(),
        "tampering must fail"
    );
}

#[test]
fn password_multi_chunk_round_trip() {
    let opts = PasswordOptions {
        chunk_size: 64, // tiny, to force several chunks
        ..fast_opts()
    };
    let pw = b"pw";
    let pt: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let ct = encrypt_password_bytes(pw, &opts, &pt).unwrap();
    let back = decrypt_password_bytes(pw, &ct).unwrap();
    assert_eq!(back, pt);
}

#[test]
fn block_transform_round_trips() {
    let key = [0x11u8; 32];
    let tweak = [0u8; 16];
    let block = [0x22u8; 32];
    let ct = block_transform(&key, &tweak, &block, false).unwrap();
    let pt = block_transform(&key, &tweak, &ct, true).unwrap();
    assert_eq!(pt, block);
    assert_ne!(ct, block);
}

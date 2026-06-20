use super::*;
use crate::format::Header;
use crate::kdf::{KdfParams, PrfId};
use std::io::Cursor;

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
fn every_mac_round_trips_and_rejects() {
    for mac in [MacId::Skein512, MacId::HmacSha256, MacId::Blake3] {
        let opts = PasswordOptions { mac, ..fast_opts() };
        let pw = b"pw";
        let pt = b"plaintext authenticated by each MAC in turn";

        let ct = encrypt_password_bytes(pw, &opts, pt).unwrap();
        let back = decrypt_password_bytes(pw, &ct).unwrap();
        assert_eq!(&back[..], &pt[..], "{mac:?} round-trip");

        assert!(
            decrypt_password_bytes(b"wrong", &ct).is_err(),
            "{mac:?} wrong password"
        );
        let mut tampered = ct.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_password_bytes(pw, &tampered).is_err(),
            "{mac:?} tampering"
        );
    }
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

#[test]
fn block_transform_rejects_bad_lengths() {
    let tweak = [0u8; 16];
    assert!(
        block_transform(&[0u8; 7], &tweak, &[0u8; 7], false).is_err(),
        "an invalid key length must fail"
    );
    assert!(
        block_transform(&[0u8; 32], &tweak, &[0u8; 16], false).is_err(),
        "a block not matching the variant block size must fail"
    );
}

// --- Streaming security properties: tampering and truncation must be rejected,
// never silently accepted. These exercise the chunked authenticated format.

#[test]
fn rejects_truncation() {
    let opts = PasswordOptions {
        chunk_size: 64, // force several frames
        ..fast_opts()
    };
    let pw = b"pw";
    let pt: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let ct = encrypt_password_bytes(pw, &opts, &pt).unwrap();

    // Dropping trailing bytes (a partial tag, a whole final frame, etc.) must
    // always error: a missing authenticated last chunk is detected.
    for cut in [1usize, 33, 80, 150] {
        let truncated = &ct[..ct.len() - cut];
        assert!(
            decrypt_password_bytes(pw, truncated).is_err(),
            "truncation by {cut} bytes must fail"
        );
    }
}

#[test]
fn rejects_header_tampering() {
    let opts = fast_opts();
    let pw = b"pw";
    let ct = encrypt_password_bytes(pw, &opts, b"a short secret").unwrap();

    // Flip a salt byte: the header parses fine, but it changes the derived key
    // and is bound into chunk 0's tag, so verification must fail.
    let mut tampered = ct.clone();
    tampered[20] ^= 1;
    assert!(decrypt_password_bytes(pw, &tampered).is_err());
}

#[test]
fn rejects_early_chunk_tampering() {
    let opts = PasswordOptions {
        chunk_size: 64,
        ..fast_opts()
    };
    let pw = b"pw";
    let pt: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let ct = encrypt_password_bytes(pw, &opts, &pt).unwrap();

    // Flip a byte roughly inside the first chunk's ciphertext; its tag must
    // reject it before any later chunk is decrypted.
    let mut tampered = ct.clone();
    let pos = ct.len() / 3;
    tampered[pos] ^= 1;
    assert!(decrypt_password_bytes(pw, &tampered).is_err());
}

// --- Raw-key CTR path ---

#[test]
fn raw_ctr_round_trips_across_the_buffer_boundary() {
    let key = [0x11u8; 32];
    let tweak = [0u8; 16];
    let iv = [0u8; 32];
    // Larger than the 64 KiB raw buffer so the streaming loop runs several times
    // and ends on a partial read.
    let pt: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();

    let mut ct = Vec::new();
    raw_ctr_stream(
        Variant::T256,
        &key,
        &tweak,
        &iv,
        &mut Cursor::new(&pt),
        &mut ct,
    )
    .unwrap();
    assert_ne!(ct, pt, "ciphertext differs from plaintext");

    let mut back = Vec::new();
    raw_ctr_stream(
        Variant::T256,
        &key,
        &tweak,
        &iv,
        &mut Cursor::new(&ct),
        &mut back,
    )
    .unwrap();
    assert_eq!(back, pt, "CTR is symmetric, so the same call decrypts");
}

#[test]
fn raw_ctr_rejects_wrong_key_length() {
    let mut out = Vec::new();
    let err = raw_ctr_stream(
        Variant::T256,
        &[0u8; 16], // a 256-bit variant needs a 32-byte key
        &[0u8; 16],
        &[0u8; 32],
        &mut Cursor::new(b"data".as_slice()),
        &mut out,
    );
    assert!(err.is_err());
}

// --- block_transform across the larger variants ---

#[test]
fn block_transform_round_trips_512_and_1024() {
    for len in [64usize, 128] {
        let key = vec![0x11u8; len];
        let tweak = [0u8; 16];
        let block = vec![0x22u8; len];
        let ct = block_transform(&key, &tweak, &block, false).unwrap();
        let pt = block_transform(&key, &tweak, &ct, true).unwrap();
        assert_eq!(pt, block, "{len}-byte block round-trips");
        assert_ne!(ct, block);
    }
}

// --- Every variant through the full password container ---

#[test]
fn password_round_trip_each_variant() {
    for variant in [Variant::T256, Variant::T512, Variant::T1024] {
        let opts = PasswordOptions {
            variant,
            ..fast_opts()
        };
        let pt = b"payload exercising each Threefish width";
        let ct = encrypt_password_bytes(b"pw", &opts, pt).unwrap();
        let back = decrypt_password_bytes(b"pw", &ct).unwrap();
        assert_eq!(&back[..], &pt[..], "{variant:?} round-trip");
    }
}

#[test]
fn decrypt_rejects_invalid_chunk_size_in_header() {
    // A chunk size that is not a multiple of the block size must be rejected
    // before any key derivation happens.
    let header = Header {
        version: crate::format::VERSION,
        variant: Variant::T256,
        kdf: KdfParams::Pbkdf2 {
            rounds: 1,
            prf: PrfId::HmacSha256,
        },
        mac: MacId::Skein512,
        chunk_size: 33, // not a multiple of 32
        salt: vec![0u8; 16],
        tweak: [0u8; 16],
        iv: vec![0u8; 32],
        label: Vec::new(),
    };
    let mut data = header.to_bytes();
    data.extend_from_slice(&[1, 0, 0, 0, 0]); // a dummy final-frame header
    let err = decrypt_password_bytes(b"pw", &data).unwrap_err();
    assert!(
        err.to_string().contains("chunk size"),
        "unexpected error: {err}"
    );
}

#[test]
fn label_round_trips_and_expect_label_is_enforced() {
    let opts = PasswordOptions {
        label: b"backup-2026-06.tar".to_vec(),
        ..fast_opts()
    };
    let pt = b"labeled payload";
    let ct = encrypt_password_bytes(b"pw", &opts, pt).unwrap();

    // The label is visible without a password, and authenticated.
    let info = inspect_bytes(&ct).unwrap();
    assert_eq!(info.label, b"backup-2026-06.tar");
    assert_eq!(info.version, crate::format::VERSION);

    // Decryption with no expected label, or the matching one, succeeds.
    assert_eq!(decrypt_password_bytes(b"pw", &ct).unwrap(), pt);
    assert_eq!(
        decrypt_password_bytes_expecting(b"pw", Some(b"backup-2026-06.tar"), &ct).unwrap(),
        pt
    );

    // A mismatched expected label fails before emitting plaintext.
    assert!(
        decrypt_password_bytes_expecting(b"pw", Some(b"other-file"), &ct).is_err(),
        "label mismatch must be rejected"
    );

    // Tampering with the stored label breaks authentication (header is bound
    // into chunk 0's tag).
    let mut tampered = ct.clone();
    let pos = tampered.iter().position(|&b| b == b'b').unwrap();
    tampered[pos] ^= 1;
    assert!(decrypt_password_bytes(b"pw", &tampered).is_err());
}

// --- Public hex/variant helpers used by the CLI ---

#[test]
fn parse_hex_accepts_valid_and_rejects_malformed() {
    assert_eq!(parse_hex("00ff a5").unwrap(), vec![0x00, 0xff, 0xa5]);
    assert_eq!(parse_hex("").unwrap(), Vec::<u8>::new());
    assert!(parse_hex("abc").is_err(), "odd digit count");
    assert!(parse_hex("zz").is_err(), "invalid digit");
}

#[test]
fn parse_tweak_requires_exactly_16_bytes() {
    let t = parse_tweak("000102030405060708090a0b0c0d0e0f").unwrap();
    assert_eq!(t[0], 0x00);
    assert_eq!(t[15], 0x0f);
    assert!(parse_tweak("00").is_err(), "too short");
    assert!(parse_tweak("0g").is_err(), "invalid hex propagates");
}

#[test]
fn variant_from_key_len_maps_all_sizes() {
    assert_eq!(variant_from_key_len(32).unwrap(), Variant::T256);
    assert_eq!(variant_from_key_len(64).unwrap(), Variant::T512);
    assert_eq!(variant_from_key_len(128).unwrap(), Variant::T1024);
    assert!(variant_from_key_len(40).is_err());
}

#[test]
fn inspect_reports_header_without_decrypting() {
    let opts = PasswordOptions {
        variant: Variant::T512,
        mac: MacId::Blake3,
        chunk_size: 4096,
        ..fast_opts()
    };
    let ct = encrypt_password_bytes(b"pw", &opts, b"secret payload").unwrap();

    // inspect needs no password and reveals only the non-secret parameters.
    let info = inspect_bytes(&ct).unwrap();
    assert_eq!(info.variant, Variant::T512);
    assert_eq!(info.mac, MacId::Blake3);
    assert_eq!(info.chunk_size, 4096);
    assert_eq!(info.salt_len, 16);

    // A non-container is rejected.
    assert!(inspect_bytes(b"not a dorado file").is_err());
}

// --- Env-knob resolution (pure helpers, so no env state is touched) ---

#[test]
fn chunk_cap_resolves_and_clamps() {
    // Default when unset or unparseable.
    assert_eq!(chunk_cap_from(None), DEFAULT_MAX_CHUNK_BYTES);
    assert_eq!(chunk_cap_from(Some("garbage")), DEFAULT_MAX_CHUNK_BYTES);
    // A plain value passes through (whitespace trimmed).
    assert_eq!(chunk_cap_from(Some("65536")), 65536);
    assert_eq!(chunk_cap_from(Some("  1048576  ")), 1_048_576);
    // It can only tighten: clamped into (0, MAX_CHUNK_BYTES].
    assert_eq!(chunk_cap_from(Some("0")), 1);
    assert_eq!(chunk_cap_from(Some("4294967295")), MAX_CHUNK_BYTES);
}

#[test]
fn rng_kind_resolves_and_rejects_unknown() {
    assert!(matches!(rng_kind(None), Ok(RngKind::Os)));
    assert!(matches!(rng_kind(Some("")), Ok(RngKind::Os)));
    assert!(matches!(rng_kind(Some("os")), Ok(RngKind::Os)));
    assert!(matches!(rng_kind(Some("thread")), Ok(RngKind::Thread)));
    assert!(rng_kind(Some("bogus")).is_err());
}

#[test]
fn auth_failure_does_not_distinguish_wrong_password_from_tampering() {
    // Both surface the same message, so neither leaks which case occurred.
    let opts = fast_opts();
    let ct = encrypt_password_bytes(b"pw", &opts, b"secret").unwrap();
    let wrong = decrypt_password_bytes(b"nope", &ct).unwrap_err();
    let mut tampered = ct.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let tamper = decrypt_password_bytes(b"pw", &tampered).unwrap_err();
    assert!(matches!(wrong, Error::AuthFailed));
    assert!(matches!(tamper, Error::AuthFailed));
    assert_eq!(wrong.to_string(), tamper.to_string());
}

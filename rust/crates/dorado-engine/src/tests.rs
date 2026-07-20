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

// --- Raw-key authenticated CTR path (encrypt-then-MAC, caller-supplied key) ---

fn raw_auth_fixture() -> (Variant, [u8; 32], [u8; 16], [u8; 32]) {
    (Variant::T256, [0x11u8; 32], [0u8; 16], [0x02u8; 32])
}

#[test]
fn raw_authenticated_round_trips_and_rejects_wrong_key() {
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let pt = b"a message that spans more than nothing";

    let ct = encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, pt)
        .unwrap();
    assert_ne!(&ct[..], &pt[..]);

    let back =
        decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, &ct)
            .unwrap();
    assert_eq!(&back[..], &pt[..]);

    let wrong_key = [0x99u8; 32];
    assert!(
        decrypt_raw_authenticated_bytes(
            variant,
            &wrong_key,
            &tweak,
            &iv,
            MacId::Skein512,
            4096,
            &ct
        )
        .is_err(),
        "wrong key must fail"
    );

    let mut tampered = ct.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        decrypt_raw_authenticated_bytes(
            variant,
            &key,
            &tweak,
            &iv,
            MacId::Skein512,
            4096,
            &tampered
        )
        .is_err(),
        "tampering must fail"
    );
}

#[test]
fn raw_authenticated_ciphertext_differs_from_bare_raw_ctr() {
    // Same key/tweak/iv into both paths must not produce related output on the
    // ciphertext bytes preceding the tag, confirming the encryption subkey (not
    // the raw key itself) drives the keystream.
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let pt = b"identical plaintext into both raw paths";

    let bare = {
        let mut out = Vec::new();
        raw_ctr_stream(variant, &key, &tweak, &iv, &mut Cursor::new(pt), &mut out).unwrap();
        out
    };
    let authenticated =
        encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, pt)
            .unwrap();

    assert_ne!(
        &authenticated[..bare.len()],
        &bare[..],
        "the authenticated path must derive its own encryption subkey, not reuse the raw key directly"
    );
}

#[test]
fn raw_authenticated_every_mac_round_trips_and_rejects() {
    let (variant, key, tweak, iv) = raw_auth_fixture();
    for mac in [MacId::Skein512, MacId::HmacSha256, MacId::Blake3] {
        let pt = b"plaintext authenticated by each MAC in turn";
        let ct =
            encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, mac, 4096, pt).unwrap();
        let back =
            decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, mac, 4096, &ct).unwrap();
        assert_eq!(&back[..], &pt[..], "{mac:?} round-trip");

        let mut tampered = ct.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, mac, 4096, &tampered)
                .is_err(),
            "{mac:?} tampering"
        );
    }
}

#[test]
fn raw_authenticated_every_variant_round_trips() {
    for (variant, key) in [
        (Variant::T256, vec![0x11u8; 32]),
        (Variant::T512, vec![0x11u8; 64]),
        (Variant::T1024, vec![0x11u8; 128]),
    ] {
        let tweak = [0u8; 16];
        let iv = vec![0x02u8; variant.block_len()];
        let pt = b"payload exercising each Threefish width";
        let ct =
            encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, pt)
                .unwrap();
        let back =
            decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, &ct)
                .unwrap();
        assert_eq!(&back[..], &pt[..], "{variant:?} round-trip");
    }
}

#[test]
fn raw_authenticated_multi_chunk_round_trip_and_rejects_early_chunk_tampering() {
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let pt: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let ct = encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 64, &pt)
        .unwrap();
    let back =
        decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 64, &ct)
            .unwrap();
    assert_eq!(back, pt);

    // Flip a byte roughly inside the first chunk's ciphertext; its tag must
    // reject it before any later chunk is decrypted.
    let mut tampered = ct.clone();
    let pos = ct.len() / 3;
    tampered[pos] ^= 1;
    assert!(decrypt_raw_authenticated_bytes(
        variant,
        &key,
        &tweak,
        &iv,
        MacId::Skein512,
        64,
        &tampered
    )
    .is_err());
}

#[test]
fn raw_authenticated_rejects_truncation() {
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let pt: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    let ct = encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 64, &pt)
        .unwrap();

    for cut in [1usize, 33, 80, 150] {
        let truncated = &ct[..ct.len() - cut];
        assert!(
            decrypt_raw_authenticated_bytes(
                variant,
                &key,
                &tweak,
                &iv,
                MacId::Skein512,
                64,
                truncated
            )
            .is_err(),
            "truncation by {cut} bytes must fail"
        );
    }
}

#[test]
fn raw_authenticated_rejects_mismatched_tweak_or_iv() {
    // Neither is stored anywhere (raw mode has no header): both are bound into
    // frame 0's AAD, so decrypting with the wrong one must fail rather than
    // silently produce wrong plaintext.
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let pt = b"bound parameters must not be swappable";
    let ct = encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, MacId::Skein512, 4096, pt)
        .unwrap();

    let other_tweak = [0x7fu8; 16];
    assert!(
        decrypt_raw_authenticated_bytes(
            variant,
            &key,
            &other_tweak,
            &iv,
            MacId::Skein512,
            4096,
            &ct
        )
        .is_err(),
        "a mismatched tweak must fail"
    );

    let other_iv = [0x7fu8; 32];
    assert!(
        decrypt_raw_authenticated_bytes(
            variant,
            &key,
            &tweak,
            &other_iv,
            MacId::Skein512,
            4096,
            &ct
        )
        .is_err(),
        "a mismatched iv must fail"
    );
}

#[test]
fn raw_authenticated_rejects_wrong_key_length() {
    let tweak = [0u8; 16];
    let iv = [0u8; 32];
    let err = encrypt_raw_authenticated_bytes(
        Variant::T256,
        &[0u8; 16], // a 256-bit variant needs a 32-byte key
        &tweak,
        &iv,
        MacId::Skein512,
        4096,
        b"data",
    );
    assert!(err.is_err());
}

#[test]
fn raw_authenticated_auth_failure_does_not_distinguish_wrong_key_from_tampering() {
    let (variant, key, tweak, iv) = raw_auth_fixture();
    let ct = encrypt_raw_authenticated_bytes(
        variant,
        &key,
        &tweak,
        &iv,
        MacId::Skein512,
        4096,
        b"secret",
    )
    .unwrap();

    let wrong_key = [0x99u8; 32];
    let wrong = decrypt_raw_authenticated_bytes(
        variant,
        &wrong_key,
        &tweak,
        &iv,
        MacId::Skein512,
        4096,
        &ct,
    )
    .unwrap_err();

    let mut tampered = ct.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let tamper = decrypt_raw_authenticated_bytes(
        variant,
        &key,
        &tweak,
        &iv,
        MacId::Skein512,
        4096,
        &tampered,
    )
    .unwrap_err();

    assert!(matches!(wrong, Error::AuthFailed));
    assert!(matches!(tamper, Error::AuthFailed));
    assert_eq!(wrong.to_string(), tamper.to_string());
}

#[test]
fn raw_authenticated_matches_cross_language_vectors() {
    // The six known-answer vectors from docs/fixtures/raw-authenticated.md (at
    // the repo root), which every other port's suite already embeds. Pinning
    // them here too gives the generator itself a regression test: the Rust
    // reference can no longer drift from the vectors it produced without a
    // failure on its own side. Common inputs: key = 0x11 repeated to the
    // variant's key length, iv = 0x02 repeated likewise, tweak = 16 zero bytes.
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    let single_pt: &[u8] = b"exercising the raw authenticated construction across languages";
    // The multichunk plaintext: a 214-byte sentence padded with 1200 'x' bytes
    // to 1414 bytes, spanning two 1 KiB chunks.
    let mut multi_pt = b"a longer payload meant to span multiple one-kilobyte authenticated \
chunks so the cross-language fixture also exercises the continuous counter and \
per-frame tagging across chunk boundaries, not just a single frame. "
        .to_vec();
    multi_pt.resize(multi_pt.len() + 1200, b'x');
    struct Vector<'a> {
        name: &'a str,
        variant: Variant,
        mac: MacId,
        chunk_size: u32,
        plaintext: &'a [u8],
        ciphertext_hex: &'a str,
    }
    let cases = [
        Vector {
            name: "t256_skein_single",
            variant: Variant::T256,
            mac: MacId::Skein512,
            chunk_size: 64 * 1024,
            plaintext: single_pt,
            ciphertext_hex:
                "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64\
             035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3\
             aba580a70532ad6b83e8fc1050620de95d5ba50e545621",
        },
        Vector {
            name: "t256_hmac_single",
            variant: Variant::T256,
            mac: MacId::HmacSha256,
            chunk_size: 64 * 1024,
            plaintext: single_pt,
            ciphertext_hex:
                "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64\
             035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8968381b4daded95b3113\
             77792e768eee91a63e2346b585ac3eda337afd6ed6dfff",
        },
        Vector {
            name: "t256_blake3_single",
            variant: Variant::T256,
            mac: MacId::Blake3,
            chunk_size: 64 * 1024,
            plaintext: single_pt,
            ciphertext_hex:
                "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64\
             035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a\
             0dd0de969ab2bf00e7d04304b45fb53984b5e29deb9834",
        },
        Vector {
            name: "t512_skein_single",
            variant: Variant::T512,
            mac: MacId::Skein512,
            chunk_size: 64 * 1024,
            plaintext: single_pt,
            ciphertext_hex:
                "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7e\
             a842953feb5ebf6aec6b95d17c646a8294b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a\
             8be5fd71b60863900177af52c649ede00952bde11f1394",
        },
        Vector {
            name: "t1024_skein_single",
            variant: Variant::T1024,
            mac: MacId::Skein512,
            chunk_size: 64 * 1024,
            plaintext: single_pt,
            ciphertext_hex:
                "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85\
             cd899f2a52b005a0fb1105fe6706ceb7f937573662a11b14b53c939c8ade26889e72113babe3\
             236093b8855432a67c45888b131be41f72cd890a724f0f",
        },
        Vector {
            name: "t256_skein_multichunk",
            variant: Variant::T256,
            mac: MacId::Skein512,
            chunk_size: 1024,
            plaintext: &multi_pt[..],
            ciphertext_hex:
                "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f83431\
             0c46654feabc437288741b5f16b5ff8bab79018d524a3a5bc2f307b486959bdb2b43f608b3a6\
             24af1d302506d312ff8c536eee10f553ab87e39697249ea5f92050c9ee832a8c8c2d7e4dffba\
             0d5b3650a65d4ec8ef92c6ec60d2030c334e56e091654db2e1ad8e3cbc921f7092bc34afc8d4\
             1226526e31b1da8240da06169ef5643695b82247984b334e4842a34b88789ff0886098e00252\
             1245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e0de9fd4810f7077c85a8ac7d\
             d49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb6257179d8\
             83d55cf7b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbd\
             f9d798338cf01a20326fc4c4d9e0ce7d874cd0f6b5bc493dcfaac173f8259f597a1d28c72e92\
             e2b47a7573857e0dd47b1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334cc319\
             ab9d06830edccd3bca5ef2e69769a4d2a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6\
             684a2ef8596c0cf60ba76834ce054fb4f7e524df218c21c2f552f74e445efbbc24c8b29df788\
             c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a69ca4c0f8b111d5213ef4\
             d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd010334928380060453213fde3\
             90d7d1b36f0f34242b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0\
             d73ba734da002a4c1fdf9613c25556ed9cb350f1d17a863ddb72a13688f51e7e56f9f6d97fcf\
             1b7f050c4a5f45c0760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229f\
             d9db1b55dad18a30bc67f3b4670a35b9c17884feb94f6c7b1183faadb7c60768c34e098754d5\
             9ce4b057249e5a7e0fc37a84925d8582a996e3ff38a3e844711f444a8ad1bbcda549b9d3b3d1\
             f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb35bccb5bc5b16053506d66c01\
             71417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e090a1442f3a99b\
             46ffcb2db05ae459912ace292e382feddede89ce478b2f09072e8415442d5208e7be684406bc\
             d8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4354275ac62acc6e797e7\
             8c6255fc4aa500776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3\
             368d45913b2e1cac5e4b6c6c790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f\
             6fab39d77d8da052a1aec80b115391f717475e9f8ab01ca3a2e7f4ed45e15cb8590c01f6274a\
             ae9b75e3852fce44b07f41bfe18777395112bbafbfab1be72df1be7a16e502d3385ff547f083\
             bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a41673617ea43d010000\
             018657d51b2abd9a7809306c46b7c1020a729dd1efddc182b7412e45fae64f45b3e33ad6440f\
             1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014fa545baa6a184\
             836a082798c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e0\
             77b1a2ded34f9e30eea332309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399\
             ebd1c4407432af717dd7b949f8eee02cf4dca067b4b6cd7f50dd53b8bff3e35af9352d0d62b3\
             ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f682ff312690bf64c277bad2ab306931e9\
             7e23dd5790127921af7d16617456c585b835117b08621c40dddd38929d0728da224e31dd1d2d\
             5461b2ce6e162f41436c92b5515223aa3f9572ab9ede606fb0c2c94545cc6221179aa6c11508\
             e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9bdd8\
             61c71319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb\
             886e7412cd9137451c75ace33797024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c\
             4309170d8192",
        },
    ];
    for v in cases {
        let Vector {
            name,
            variant,
            mac,
            chunk_size,
            plaintext: pt,
            ciphertext_hex: ct_hex,
        } = v;
        let want = unhex(&ct_hex.replace(char::is_whitespace, ""));
        let key = vec![0x11u8; variant.key_len()];
        let iv = vec![0x02u8; variant.block_len()];
        let tweak = [0u8; 16];
        let ct = encrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, mac, chunk_size, pt)
            .unwrap();
        assert_eq!(
            ct, want,
            "{name}: ciphertext must match the published vector"
        );
        let back =
            decrypt_raw_authenticated_bytes(variant, &key, &tweak, &iv, mac, chunk_size, &ct)
                .unwrap();
        assert_eq!(
            back, pt,
            "{name}: the vector decrypts back to its plaintext"
        );
    }
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

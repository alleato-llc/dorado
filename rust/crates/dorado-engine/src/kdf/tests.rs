use super::*;

#[test]
fn pbkdf2_is_deterministic_and_salt_sensitive() {
    let params = KdfParams::Pbkdf2 {
        rounds: 1000,
        prf: PrfId::HmacSha256,
    };
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    derive_from_password(&params, b"password", b"saltsalt", &mut a).unwrap();
    derive_from_password(&params, b"password", b"saltsalt", &mut b).unwrap();
    assert_eq!(a, b, "same inputs must give the same key");

    let mut c = [0u8; 32];
    derive_from_password(&params, b"password", b"different", &mut c).unwrap();
    assert_ne!(a, c, "a different salt must give a different key");
}

#[test]
fn scrypt_and_argon2_run_with_small_params() {
    // Tiny parameters keep the test fast; production defaults are larger.
    let mut out = [0u8; 32];
    derive_from_password(
        &KdfParams::Scrypt {
            log_n: 8,
            r: 8,
            p: 1,
        },
        b"password",
        b"saltsalt",
        &mut out,
    )
    .unwrap();
    derive_from_password(
        &KdfParams::Argon2id {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        b"password",
        b"saltsalt",
        &mut out,
    )
    .unwrap();
}

#[test]
fn scrypt_derives_more_than_64_bytes() {
    // The 1024 variant needs 128 + 32 = 160 bytes of key material, which is
    // past the limit on scrypt's Params `len` field.
    let mut out = [0u8; 160];
    derive_from_password(
        &KdfParams::Scrypt {
            log_n: 8,
            r: 8,
            p: 1,
        },
        b"password",
        b"saltsalt",
        &mut out,
    )
    .unwrap();
    assert!(out.iter().any(|&b| b != 0), "output should be filled");
}

#[test]
fn derive_from_key_is_deterministic_and_domain_separated() {
    let master = [0x42u8; 32];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    derive_from_key(&master, "myapp/index", &mut a);
    derive_from_key(&master, "myapp/index", &mut b);
    assert_eq!(a, b, "same key + domain must give the same bytes");

    let mut c = [0u8; 32];
    derive_from_key(&master, "myapp/data", &mut c);
    assert_ne!(a, c, "a different domain must give a different key");

    let other = [0x43u8; 32];
    let mut d = [0u8; 32];
    derive_from_key(&other, "myapp/index", &mut d);
    assert_ne!(a, d, "a different master must give a different key");

    // Children reveal nothing about each other or the master: at minimum,
    // none of them may equal the master or one another.
    assert_ne!(a, master);
    assert_ne!(c, master);
}

#[test]
fn derive_from_key_supports_arbitrary_output_lengths() {
    // The 1024-bit variant's raw mode needs 128-byte keys; Skein's output
    // length is free, so longer outputs must work and must not merely
    // prefix-extend shorter ones (the length is bound into the hash).
    let master = [0x42u8; 32];
    let mut short = [0u8; 32];
    let mut long = [0u8; 128];
    derive_from_key(&master, "myapp/index", &mut short);
    derive_from_key(&master, "myapp/index", &mut long);
    assert_ne!(
        short,
        long[..32],
        "output length is part of Skein's config, not a truncation"
    );
}

#[test]
fn derive_from_key_default_matches_skein_prf() {
    // derive_from_key is defined as derive_from_key_with(Skein512, ..); the two
    // must be byte-for-byte identical so the default is never a silent change.
    let master = [0x42u8; 32];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    derive_from_key(&master, "myapp/index", &mut a);
    derive_from_key_with(KdfPrf::Skein512, &master, "myapp/index", &mut b);
    assert_eq!(a, b);
}

#[test]
fn derive_from_key_with_blake3_is_deterministic_domain_separated_and_distinct() {
    let master = [0x42u8; 32];
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    derive_from_key_with(KdfPrf::Blake3, &master, "myapp/index", &mut a);
    derive_from_key_with(KdfPrf::Blake3, &master, "myapp/index", &mut b);
    assert_eq!(a, b, "same key + domain must give the same bytes");

    let mut c = [0u8; 32];
    derive_from_key_with(KdfPrf::Blake3, &master, "myapp/data", &mut c);
    assert_ne!(a, c, "a different domain must give a different key");
    assert_ne!(a, master, "a child never equals the master");

    // The two PRFs are independent functions: the same key/domain under Skein
    // and under BLAKE3 must not coincide.
    let mut skein = [0u8; 32];
    derive_from_key_with(KdfPrf::Skein512, &master, "myapp/index", &mut skein);
    assert_ne!(a, skein, "BLAKE3 and Skein fan-outs must differ");
}

#[test]
fn derive_from_key_with_blake3_supports_arbitrary_output_lengths() {
    // BLAKE3 is an XOF, so any output length works and a longer output must not
    // merely prefix-extend a shorter one (the length is bound into the hash).
    let master = [0x42u8; 32];
    let mut short = [0u8; 32];
    let mut long = [0u8; 128];
    derive_from_key_with(KdfPrf::Blake3, &master, "myapp/index", &mut short);
    derive_from_key_with(KdfPrf::Blake3, &master, "myapp/index", &mut long);
    assert_eq!(
        short,
        long[..32],
        "BLAKE3 is an XOF: a shorter output is the prefix of a longer one"
    );
}

#[test]
#[should_panic(expected = "32-byte key")]
fn derive_from_key_with_blake3_rejects_non_32_byte_key() {
    let mut out = [0u8; 32];
    derive_from_key_with(KdfPrf::Blake3, &[0u8; 16], "myapp/index", &mut out);
}

#[test]
fn validate_accepts_sane_and_rejects_absurd_params() {
    // Defaults are fine.
    validate(&KdfParams::Argon2id {
        m_cost: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    })
    .unwrap();
    validate(&KdfParams::Pbkdf2 {
        rounds: 600_000,
        prf: PrfId::HmacSha256,
    })
    .unwrap();

    // Absurd costs (as a crafted header might carry) are rejected.
    assert!(validate(&KdfParams::Argon2id {
        m_cost: 1 << 30, // ~1 TiB
        t_cost: 3,
        p_cost: 1,
    })
    .is_err());
    assert!(validate(&KdfParams::Scrypt {
        log_n: 40,
        r: 8,
        p: 1,
    })
    .is_err());
    assert!(validate(&KdfParams::Pbkdf2 {
        rounds: u32::MAX,
        prf: PrfId::HmacSha256,
    })
    .is_err());
    // Zero rounds would "derive" an all-zero key without error.
    assert!(validate(&KdfParams::Pbkdf2 {
        rounds: 0,
        prf: PrfId::HmacSha256,
    })
    .is_err());
}

#[test]
fn validate_rejects_each_absurd_argon2_and_scrypt_knob() {
    // Each individual cost knob has its own bound; exercise the ones the broad
    // test above does not (argon2 t_cost and p_cost, scrypt r and p).
    assert!(validate(&KdfParams::Argon2id {
        m_cost: 1024,
        t_cost: 1000, // > 64
        p_cost: 1,
    })
    .is_err());
    assert!(validate(&KdfParams::Argon2id {
        m_cost: 1024,
        t_cost: 3,
        p_cost: 1000, // > 16
    })
    .is_err());
    assert!(validate(&KdfParams::Scrypt {
        log_n: 15,
        r: 1000, // > 32
        p: 1,
    })
    .is_err());
    assert!(validate(&KdfParams::Scrypt {
        log_n: 15,
        r: 8,
        p: 1000, // > 16
    })
    .is_err());
}

#[test]
fn prf_id_code_round_trips() {
    assert_eq!(
        PrfId::from_code(PrfId::HmacSha256.code()).unwrap(),
        PrfId::HmacSha256
    );
    assert!(PrfId::from_code(7).is_err());
}

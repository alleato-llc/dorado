use super::*;

#[test]
fn pbkdf2_is_deterministic_and_salt_sensitive() {
    let params = KdfParams::Pbkdf2 {
        rounds: 1000,
        prf: PrfId::HmacSha256,
    };
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    derive(&params, b"password", b"saltsalt", &mut a).unwrap();
    derive(&params, b"password", b"saltsalt", &mut b).unwrap();
    assert_eq!(a, b, "same inputs must give the same key");

    let mut c = [0u8; 32];
    derive(&params, b"password", b"different", &mut c).unwrap();
    assert_ne!(a, c, "a different salt must give a different key");
}

#[test]
fn scrypt_and_argon2_run_with_small_params() {
    // Tiny parameters keep the test fast; production defaults are larger.
    let mut out = [0u8; 32];
    derive(
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
    derive(
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
    derive(
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
}

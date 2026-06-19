use super::*;

#[test]
fn header_round_trips() {
    let header = Header {
        version: VERSION,
        variant: Variant::T512,
        kdf: KdfParams::Argon2id {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        },
        mac: MacId::HmacSha256,
        chunk_size: 65536,
        salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
        tweak: [0x42; 16],
        iv: vec![0x99; 64],
        label: b"backup-2026".to_vec(),
    };
    let bytes = header.to_bytes();
    let (parsed, offset) = Header::parse(&bytes).unwrap();

    assert_eq!(offset, bytes.len(), "frames start right after header");
    assert_eq!(parsed.version, VERSION);
    assert_eq!(parsed.variant, header.variant);
    assert_eq!(parsed.mac, header.mac);
    assert_eq!(parsed.chunk_size, header.chunk_size);
    assert_eq!(parsed.salt, header.salt);
    assert_eq!(parsed.tweak, header.tweak);
    assert_eq!(parsed.iv, header.iv);
    assert_eq!(parsed.label, b"backup-2026", "v4 label round-trips");
}

#[test]
fn v3_header_reads_with_empty_label_and_no_label_field() {
    // A v3 header (version byte 3) has no trailing label field. It must still
    // parse, and re-serialize to the identical bytes (so its tag still verifies).
    let header = Header {
        version: 3,
        variant: Variant::T256,
        kdf: KdfParams::Pbkdf2 {
            rounds: 1000,
            prf: PrfId::HmacSha256,
        },
        mac: MacId::Skein512,
        chunk_size: 65536,
        salt: vec![0u8; 16],
        tweak: [0u8; 16],
        iv: vec![0u8; 32],
        label: Vec::new(),
    };
    let bytes = header.to_bytes();
    let (parsed, offset) = Header::parse(&bytes).unwrap();
    assert_eq!(parsed.version, 3);
    assert!(parsed.label.is_empty());
    assert_eq!(offset, bytes.len(), "no label field is read for v3");
    assert_eq!(parsed.to_bytes(), bytes, "v3 reserializes byte-for-byte");
}

#[test]
fn parse_carries_trailing_ciphertext_offset() {
    let header = Header {
        version: VERSION,
        variant: Variant::T256,
        kdf: KdfParams::Pbkdf2 {
            rounds: 600_000,
            prf: PrfId::HmacSha256,
        },
        mac: MacId::HmacSha256,
        chunk_size: 65536,
        salt: vec![0u8; 16],
        tweak: [0u8; 16],
        iv: vec![0u8; 32],
        label: Vec::new(),
    };
    let mut bytes = header.to_bytes();
    bytes.extend_from_slice(b"frames");
    let (_, offset) = Header::parse(&bytes).unwrap();
    assert_eq!(&bytes[offset..], b"frames");
}

#[test]
fn rejects_bad_magic_and_truncation() {
    assert!(Header::parse(b"XXXXX").is_err());
    assert!(Header::parse(b"DR").is_err());
}

#[test]
fn scrypt_and_t1024_header_round_trips() {
    // Covers the scrypt KDF encoding and the 1024 variant (its code, key length,
    // and 128-byte IV).
    let header = Header {
        version: VERSION,
        variant: Variant::T1024,
        kdf: KdfParams::Scrypt {
            log_n: 15,
            r: 8,
            p: 2,
        },
        mac: MacId::Blake3,
        chunk_size: 1 << 20,
        salt: vec![7u8; 16],
        tweak: [0xab; 16],
        iv: vec![0xcd; 128],
        label: Vec::new(),
    };
    let bytes = header.to_bytes();
    let (parsed, offset) = Header::parse(&bytes).unwrap();
    assert_eq!(offset, bytes.len());
    assert_eq!(parsed.variant, Variant::T1024);
    assert_eq!(parsed.mac, MacId::Blake3);
    assert_eq!(parsed.iv.len(), 128);
    match parsed.kdf {
        KdfParams::Scrypt { log_n, r, p } => assert_eq!((log_n, r, p), (15, 8, 2)),
        other => panic!("expected scrypt, got {other:?}"),
    }
}

#[test]
fn code_round_trips_for_all_variants_and_macs() {
    for v in [Variant::T256, Variant::T512, Variant::T1024] {
        assert_eq!(Variant::from_code(v.code()).unwrap(), v);
    }
    for m in [MacId::HmacSha256, MacId::Skein512, MacId::Blake3] {
        assert_eq!(MacId::from_code(m.code()).unwrap(), m);
    }
    assert_eq!(Variant::T1024.key_len(), 128);
    assert_eq!(Variant::T1024.block_len(), 128);
}

#[test]
fn from_code_rejects_unknown_bytes() {
    assert!(Variant::from_code(9).is_err());
    assert!(MacId::from_code(9).is_err());
    assert!(PrfId::from_code(9).is_err());
}

#[test]
fn rejects_unsupported_version_and_unknown_kdf_id() {
    let header = Header {
        version: VERSION,
        variant: Variant::T256,
        kdf: KdfParams::Pbkdf2 {
            rounds: 1000,
            prf: PrfId::HmacSha256,
        },
        mac: MacId::Skein512,
        chunk_size: 65536,
        salt: vec![0u8; 16],
        tweak: [0u8; 16],
        iv: vec![0u8; 32],
        label: Vec::new(),
    };
    let good = header.to_bytes();

    // Version sits right after the 4-byte magic.
    let mut bad_version = good.clone();
    bad_version[4] = 99;
    let err = Header::parse(&bad_version).unwrap_err();
    assert!(err.contains("version"), "got: {err}");

    // KDF id sits after magic(4) + version(1) + variant(1).
    let mut bad_kdf = good.clone();
    bad_kdf[6] = 9;
    assert!(Header::parse(&bad_kdf).is_err());
}

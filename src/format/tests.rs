use super::*;

#[test]
fn header_round_trips() {
    let header = Header {
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
    };
    let bytes = header.to_bytes();
    let (parsed, offset) = Header::parse(&bytes).unwrap();

    assert_eq!(offset, bytes.len(), "frames start right after header");
    assert_eq!(parsed.variant, header.variant);
    assert_eq!(parsed.mac, header.mac);
    assert_eq!(parsed.chunk_size, header.chunk_size);
    assert_eq!(parsed.salt, header.salt);
    assert_eq!(parsed.tweak, header.tweak);
    assert_eq!(parsed.iv, header.iv);
}

#[test]
fn parse_carries_trailing_ciphertext_offset() {
    let header = Header {
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

//! Compare dorado's Threefish-256 output against two independent references:
//! the official Crypto++ known-answer vector, and the RustCrypto `threefish`
//! crate. All three must agree on the same (key, tweak, plaintext).
//!
//! Run with: cargo run --example compare

use dorado::Threefish256;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // Official Crypto++ Threefish-256 vector (raw byte order).
    let key: [u8; 32] = unhex("101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F")
        [..]
        .try_into()
        .unwrap();
    let tweak: [u8; 16] = unhex("000102030405060708090A0B0C0D0E0F")[..]
        .try_into()
        .unwrap();
    let plaintext: [u8; 32] =
        unhex("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0")[..]
            .try_into()
            .unwrap();
    let official = unhex("E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF");

    // dorado.
    let mut mine = plaintext;
    Threefish256::new(&key, &tweak).encrypt_block(&mut mine);

    // RustCrypto `threefish`, fed the same little-endian words.
    let theirs_cipher = threefish::Threefish256::new_with_tweak(&key, &tweak);
    let mut words = [0u64; 4];
    for (w, c) in words.iter_mut().zip(plaintext.chunks_exact(8)) {
        *w = u64::from_le_bytes(c.try_into().unwrap());
    }
    theirs_cipher.encrypt_block_u64(&mut words);
    let mut theirs = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        theirs[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }

    println!("same key, tweak, and plaintext; three independent implementations:");
    println!("  dorado:            {}", hex(&mine));
    println!("  RustCrypto:        {}", hex(&theirs));
    println!("  Crypto++ vector:   {}", hex(&official));
    println!();
    println!(
        "all three identical? {}",
        mine[..] == theirs[..] && mine[..] == official[..]
    );
}

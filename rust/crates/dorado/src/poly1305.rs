//! Poly1305 one-time MAC (RFC 8439), implemented from scratch and verified
//! against the RFC's test vectors.
//!
//! Arithmetic is modulo 2^130 - 5, carried out with five 26-bit limbs (the
//! standard reference representation). Poly1305 is a ONE-TIME MAC: each key must
//! authenticate exactly one message, reusing a key is a catastrophic break. It
//! is the authenticator half of the ChaCha20-Poly1305 AEAD.

const MASK26: u32 = 0x3ff_ffff;

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}

/// Compute the 16-byte Poly1305 tag of `msg` under the 32-byte one-time `key`
/// (`r` in the low 16 bytes, `s` in the high 16).
pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Load and clamp r into 26-bit limbs.
    let t0 = le32(&key[0..4]);
    let t1 = le32(&key[4..8]);
    let t2 = le32(&key[8..12]);
    let t3 = le32(&key[12..16]);
    let r0 = t0 & 0x3ff_ffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff;
    let r4 = (t3 >> 8) & 0x000_fffff;
    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);

    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0u32, 0u32, 0u32, 0u32, 0u32);

    for chunk in msg.chunks(16) {
        // Load the block and append the high bit (a full block adds 2^128; a
        // final partial block of length n puts the 1 just past its last byte).
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let t0 = le32(&block[0..4]);
        let t1 = le32(&block[4..8]);
        let t2 = le32(&block[8..12]);
        let t3 = le32(&block[12..16]);
        let hibit = block[16] as u32;

        h0 = h0.wrapping_add(t0 & MASK26);
        h1 = h1.wrapping_add(((t0 >> 26) | (t1 << 6)) & MASK26);
        h2 = h2.wrapping_add(((t1 >> 20) | (t2 << 12)) & MASK26);
        h3 = h3.wrapping_add(((t2 >> 14) | (t3 << 18)) & MASK26);
        h4 = h4.wrapping_add((t3 >> 8) | (hibit << 24));

        // h = (h * r) mod (2^130 - 5), products in 64 bits.
        let m = |a: u32, b: u32| a as u64 * b as u64;
        let d0 = m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1);
        let d1 = m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2);
        let d2 = m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3);
        let d3 = m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4);
        let d4 = m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0);

        let c = (d0 >> 26) as u32;
        h0 = (d0 as u32) & MASK26;
        let d1 = d1 + c as u64;
        let c = (d1 >> 26) as u32;
        h1 = (d1 as u32) & MASK26;
        let d2 = d2 + c as u64;
        let c = (d2 >> 26) as u32;
        h2 = (d2 as u32) & MASK26;
        let d3 = d3 + c as u64;
        let c = (d3 >> 26) as u32;
        h3 = (d3 as u32) & MASK26;
        let d4 = d4 + c as u64;
        let c = (d4 >> 26) as u32;
        h4 = (d4 as u32) & MASK26;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        let c = h0 >> 26;
        h0 &= MASK26;
        h1 = h1.wrapping_add(c);
    }

    // Final full carry.
    let c = h1 >> 26;
    h1 &= MASK26;
    h2 += c;
    let c = h2 >> 26;
    h2 &= MASK26;
    h3 += c;
    let c = h3 >> 26;
    h3 &= MASK26;
    h4 += c;
    let c = h4 >> 26;
    h4 &= MASK26;
    h0 += c * 5;
    let c = h0 >> 26;
    h0 &= MASK26;
    h1 += c;

    // g = h - p (subtract 2^130 - 5); keep g if there was no borrow (h >= p).
    let mut g0 = h0 + 5;
    let c = g0 >> 26;
    g0 &= MASK26;
    let mut g1 = h1 + c;
    let c = g1 >> 26;
    g1 &= MASK26;
    let mut g2 = h2 + c;
    let c = g2 >> 26;
    g2 &= MASK26;
    let mut g3 = h3 + c;
    let c = g3 >> 26;
    g3 &= MASK26;
    let mut g4 = (h4 + c).wrapping_sub(1 << 26);

    // mask = all-ones if h >= p (use g), else 0 (keep h).
    let mask = (g4 >> 31).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    let nmask = !mask;
    h0 = (h0 & nmask) | g0;
    h1 = (h1 & nmask) | g1;
    h2 = (h2 & nmask) | g2;
    h3 = (h3 & nmask) | g3;
    h4 = (h4 & nmask) | g4;

    // Pack the 26-bit limbs back into 32-bit words.
    h0 |= h1 << 26;
    h1 = (h1 >> 6) | (h2 << 20);
    h2 = (h2 >> 12) | (h3 << 14);
    h3 = (h3 >> 18) | (h4 << 8);

    // tag = (h + s) mod 2^128.
    let mut f = h0 as u64 + le32(&key[16..20]) as u64;
    h0 = f as u32;
    f = h1 as u64 + le32(&key[20..24]) as u64 + (f >> 32);
    h1 = f as u32;
    f = h2 as u64 + le32(&key[24..28]) as u64 + (f >> 32);
    h2 = f as u32;
    f = h3 as u64 + le32(&key[28..32]) as u64 + (f >> 32);
    h3 = f as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&h0.to_le_bytes());
    tag[4..8].copy_from_slice(&h1.to_le_bytes());
    tag[8..12].copy_from_slice(&h2.to_le_bytes());
    tag[12..16].copy_from_slice(&h3.to_le_bytes());
    tag
}

#[cfg(test)]
mod tests;

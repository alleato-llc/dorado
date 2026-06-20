package com.alleato.dorado;

import static com.alleato.dorado.TestUtil.hex;
import static com.alleato.dorado.TestUtil.seq;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * Skein-512 known-answer tests. The empty-input and "abc" digests are the official
 * Skein 1.3 vectors; the longer ones are baked from the Rust reference (dorado).
 */
class SkeinTest {
    @Test
    void empty512() {
        assertEquals(
            "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4"
            + "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
            hex(Skein.hash(64, new byte[0])));
    }

    @Test
    void abc256() {
        assertEquals(
            "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527",
            hex(Skein.hash(32, "abc".getBytes())));
    }

    @Test
    void abc512() {
        assertEquals(
            "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f938"
            + "93ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75",
            hex(Skein.hash(64, "abc".getBytes())));
    }

    @Test
    void multiBlock256() {
        assertEquals(
            "15096f2f503dce8eab3ab3ac80d840dafdd8001ca1737fab69b717475b4abdaf",
            hex(Skein.hash(32, seq(500))));
    }

    @Test
    void keyedMac() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x9c);
        assertEquals(
            "8b0865bcabf2dec950b2178b5127e88914d039a0681339e5d10e06d95bad12b3",
            hex(Skein.mac(key, 32, "authenticate me".getBytes())));
    }

    @Test
    void macIsKeyAndMessageSensitive() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x9c);
        byte[] other = new byte[32];
        java.util.Arrays.fill(other, (byte) 0x22);
        byte[] a = Skein.mac(key, 32, "authenticate me".getBytes());
        assertNotEquals(hex(a), hex(Skein.mac(other, 32, "authenticate me".getBytes())));
        assertNotEquals(hex(a), hex(Skein.mac(key, 32, "authenticate ne".getBytes())));
    }
}

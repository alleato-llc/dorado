package com.alleato.dorado;

import static com.alleato.dorado.TestUtil.hex;
import static com.alleato.dorado.TestUtil.seq;
import static com.alleato.dorado.TestUtil.unhex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Known-answer tests against the official Skein 1.3 Threefish vectors (the same
 * vectors the Rust reference is checked against), for each block size, plus a CTR
 * round-trip.
 */
class ThreefishTest {
    private static final String TWEAK = "000102030405060708090A0B0C0D0E0F";

    private static final String KEY256 = "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F";
    private static final String PT256 = "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0";
    private static final String CT256 = "E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF";

    private static final String KEY512 =
        "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F"
        + "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F";
    private static final String PT512 =
        "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"
        + "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0";
    private static final String CT512 =
        "E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779"
        + "272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D";

    private static final String KEY1024 =
        "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F"
        + "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F"
        + "505152535455565758595A5B5C5D5E5F6061626364656667 68696A6B6C6D6E6F"
        + "707172737475767778797A7B7C7D7E7F8081828384858687 88898A8B8C8D8E8F";
    private static final String PT1024 =
        "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"
        + "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"
        + "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0"
        + "9F9E9D9C9B9A99989796959493929190 8F8E8D8C8B8A89888786858483828180";
    private static final String CT1024 =
        "A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C"
        + "94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD"
        + "8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8"
        + "3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE";

    private static void kat(Threefish c, String ptHex, String ctHex) {
        byte[] pt = unhex(ptHex);
        byte[] ct = unhex(ctHex);
        byte[] got = new byte[pt.length];
        c.encryptBlock(got, pt);
        assertEquals(ctHex.replace(" ", "").toLowerCase(), hex(got), "encrypt");
        byte[] back = new byte[ct.length];
        c.decryptBlock(back, ct);
        assertArrayEquals(pt, back, "decrypt round-trip");
    }

    @Test
    void kat256() {
        kat(Threefish.t256(unhex(KEY256), unhex(TWEAK)), PT256, CT256);
    }

    @Test
    void kat512() {
        kat(Threefish.t512(unhex(KEY512), unhex(TWEAK)), PT512, CT512);
    }

    @Test
    void kat1024() {
        kat(Threefish.t1024(unhex(KEY1024), unhex(TWEAK)), PT1024, CT1024);
    }

    @Test
    void ctrRoundTripAnyLength() {
        byte[] key = seq(32);
        byte[] tweak = new byte[16];
        byte[] iv = seq(32);
        byte[] plain = "any length, not just one block -- CTR handles it".getBytes();

        byte[] ct = plain.clone();
        Threefish.t256(key, tweak).ctrApply(iv, ct);
        assertFalse(java.util.Arrays.equals(ct, plain), "ciphertext equals plaintext");

        byte[] back = ct.clone();
        Threefish.t256(key, tweak).ctrApply(iv, back);
        assertArrayEquals(plain, back);
    }

    @Test
    void rejectsWrongLengths() {
        assertThrows(IllegalArgumentException.class, () -> Threefish.t256(new byte[31], new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> Threefish.t256(new byte[32], new byte[15]));
    }
}

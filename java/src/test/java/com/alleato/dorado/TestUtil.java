package com.alleato.dorado;

import java.util.HexFormat;

/** Small helpers shared by the test suite. */
public final class TestUtil {
    private static final HexFormat HEX = HexFormat.of();

    private TestUtil() {}

    public static byte[] unhex(String s) {
        return HEX.parseHex(s.replace(" ", ""));
    }

    public static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    /** A buffer of n bytes set to 0, 1, 2, ... (mod 256). */
    public static byte[] seq(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) i;
        }
        return b;
    }
}

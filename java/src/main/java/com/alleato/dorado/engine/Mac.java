package com.alleato.dorado.engine;

import com.alleato.dorado.Blake3;
import com.alleato.dorado.Skein;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;

/**
 * The MAC menu: Skein-512 (default) and keyed BLAKE3 from this project's
 * from-scratch hashes, HMAC-SHA256 from the JDK. All three take the 32-byte MAC key
 * and produce a 32-byte tag.
 */
public final class Mac {
    private Mac() {}

    /** Compute a 32-byte tag over signed under the selected MAC. */
    public static byte[] tag(int mac, byte[] macKey, byte[] signed) {
        return switch (mac) {
            case Format.MAC_SKEIN -> Skein.mac(macKey, Format.TAG_LEN, signed);
            case Format.MAC_BLAKE3 -> Blake3.keyedMac(macKey, Format.TAG_LEN, signed);
            case Format.MAC_HMAC -> hmacSha256(macKey, signed);
            default -> throw new IllegalArgumentException("unknown mac id " + mac);
        };
    }

    /** Recompute the tag and compare it in constant time. */
    public static boolean verify(int mac, byte[] macKey, byte[] signed, byte[] received) {
        // MessageDigest.isEqual is constant-time in modern JDKs.
        return MessageDigest.isEqual(tag(mac, macKey, signed), received);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac h = javax.crypto.Mac.getInstance("HmacSHA256");
            h.init(new SecretKeySpec(key, "HmacSHA256"));
            return h.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }
}

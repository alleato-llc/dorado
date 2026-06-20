package com.alleato.dorado;

import static com.alleato.dorado.TestUtil.hex;
import static com.alleato.dorado.TestUtil.seq;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * BLAKE3 known-answer tests. The empty-input digest is the official BLAKE3 vector;
 * the multi-chunk digest and the keyed MAC are baked from the Rust reference
 * (dorado), exercising the chunk-stack tree (3000 bytes is several 1024-byte chunks).
 */
class Blake3Test {
    @Test
    void empty() {
        assertEquals(
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            hex(Blake3.hash(32, new byte[0])));
    }

    @Test
    void multiChunkTree() {
        assertEquals(
            "6c943946a70794f2e14c785d5ee88d300d5f9b91d1b4ef88302974ac4b069052",
            hex(Blake3.hash(32, seq(3000))));
    }

    @Test
    void keyedMac() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 0x9c);
        assertEquals(
            "e8a84781007d67df2b0de8cf1d0c48b0fee97a0f9744ba5b325c1aac2d670a08",
            hex(Blake3.keyedMac(key, 32, "authenticate me".getBytes())));
    }

    @Test
    void incrementalMatchesOneShot() {
        byte[] msg = seq(2500);
        Blake3.Hasher h = Blake3.Hasher.newHash();
        for (int i = 0; i < msg.length; i += 7) {
            h.update(java.util.Arrays.copyOfRange(msg, i, Math.min(i + 7, msg.length)));
        }
        byte[] streamed = new byte[32];
        h.finalizeInto(streamed);
        assertEquals(hex(Blake3.hash(32, msg)), hex(streamed));
    }
}

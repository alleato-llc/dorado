package com.alleato.dorado;

/**
 * From-scratch Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI
 * (Unique Block Iteration), the hash function Threefish was designed to power. The
 * output length is chosen per call (Skein folds it into the configuration block).
 *
 * <p>One-shot only (in memory), matching the TypeScript port; the Rust and Go ports
 * additionally stream. Java port of the dorado Rust crate's skein module.
 */
public final class Skein {
    private static final int BLOCK = 64;

    // UBI block type values (the 6-bit type field of the tweak).
    private static final long T_KEY = 0;
    private static final long T_CFG = 4;
    private static final long T_MSG = 48;
    private static final long T_OUT = 63;

    private Skein() {}

    // Build the 128-bit UBI tweak (16 little-endian bytes) for a block ending at
    // byte position, of a UBI pass of type ty, with the first/final flags.
    private static byte[] tweak(long position, long ty, boolean first, boolean last) {
        long t1 = ty << 56;
        if (first) {
            t1 |= 1L << 62;
        }
        if (last) {
            t1 |= 1L << 63;
        }
        byte[] tw = new byte[16];
        Threefish.putLe64(tw, 0, position);
        Threefish.putLe64(tw, 8, t1);
        return tw;
    }

    // Run one full UBI pass, chaining msg into the chaining value g. An empty
    // message processes a single zero block at position 0.
    private static void ubi(byte[] g, byte[] msg, long ty) {
        int total = msg.length;
        int offset = 0;
        long position = 0;
        boolean first = true;
        while (true) {
            int take = Math.min(total - offset, BLOCK);
            byte[] block = new byte[BLOCK];
            System.arraycopy(msg, offset, block, 0, take);
            position += take;
            offset += take;
            boolean last = offset >= total;

            Threefish c = Threefish.t512(g, tweak(position, ty, first, last));
            byte[] enc = new byte[BLOCK];
            c.encryptBlock(enc, block);
            for (int i = 0; i < BLOCK; i++) {
                g[i] = (byte) (enc[i] ^ block[i]);
            }
            first = false;
            if (last) {
                break;
            }
        }
    }

    // The 32-byte Skein configuration block for an output of outBits.
    private static byte[] configBlock(long outBits) {
        byte[] c = new byte[32];
        c[0] = 'S';
        c[1] = 'H';
        c[2] = 'A';
        c[3] = '3';
        c[4] = 1; // version 1 (16-bit little-endian)
        Threefish.putLe64(c, 8, outBits);
        return c;
    }

    // Fill out from the final chaining value via the output UBI over a counter.
    private static void outputInto(byte[] g, byte[] out) {
        long counter = 0;
        int written = 0;
        while (written < out.length) {
            byte[] block = g.clone();
            byte[] ctr = new byte[8];
            Threefish.putLe64(ctr, 0, counter);
            ubi(block, ctr, T_OUT);
            int n = Math.min(BLOCK, out.length - written);
            System.arraycopy(block, 0, out, written, n);
            written += n;
            counter++;
        }
    }

    /** One-shot Skein-512 hash of msg producing outLen bytes. */
    public static byte[] hash(int outLen, byte[] msg) {
        byte[] g = new byte[64];
        ubi(g, configBlock((long) outLen * 8), T_CFG);
        ubi(g, msg, T_MSG);
        byte[] out = new byte[outLen];
        outputInto(g, out);
        return out;
    }

    /** One-shot Skein-512 keyed MAC producing outLen bytes (key absorbed first). */
    public static byte[] mac(byte[] key, int outLen, byte[] msg) {
        byte[] g = new byte[64];
        if (key.length > 0) {
            ubi(g, key, T_KEY);
        }
        ubi(g, configBlock((long) outLen * 8), T_CFG);
        ubi(g, msg, T_MSG);
        byte[] out = new byte[outLen];
        outputInto(g, out);
        return out;
    }
}

package com.alleato.dorado;

/**
 * From-scratch Threefish (256/512/1024-bit), the tweakable block cipher at the
 * core of Skein, following the Skein 1.3 specification (including the round-3 NIST
 * tweak to the key-schedule constant C240), plus CTR mode. This is the Java port
 * of the dorado Rust crate; keys, tweaks, and blocks are little-endian.
 *
 * <p>Java's {@code long} is a native 64-bit two's-complement integer, so {@code +},
 * {@code ^}, and {@code Long.rotateLeft} are bit-identical to the unsigned ops the
 * cipher needs. Educational and unaudited.
 */
public final class Threefish {
    /** Skein 1.3 key-schedule constant (the round-3 NIST value). Do not change. */
    private static final long C240 = 0x1BD11BDAA9FC1A22L;

    // Per-variant rotation and permutation tables (Skein 1.3). Verified against
    // official test vectors and must not be changed.
    private static final int[][] ROT256 = {
        {14, 52, 23, 5, 25, 46, 58, 32},
        {16, 57, 40, 37, 33, 12, 22, 32},
    };
    private static final int[] PERM256 = {0, 3, 2, 1};

    private static final int[][] ROT512 = {
        {46, 33, 17, 44, 39, 13, 25, 8},
        {36, 27, 49, 9, 30, 50, 29, 35},
        {19, 14, 36, 54, 34, 10, 39, 56},
        {37, 42, 39, 56, 24, 17, 43, 22},
    };
    private static final int[] PERM512 = {2, 1, 4, 7, 6, 5, 0, 3};

    private static final int[][] ROT1024 = {
        {24, 38, 33, 5, 41, 16, 31, 9},
        {13, 19, 4, 20, 9, 34, 44, 48},
        {8, 10, 51, 48, 37, 56, 47, 35},
        {47, 55, 13, 41, 31, 51, 46, 52},
        {8, 49, 34, 47, 12, 4, 19, 23},
        {17, 18, 41, 28, 47, 53, 42, 31},
        {22, 23, 59, 16, 44, 42, 44, 37},
        {37, 52, 17, 25, 30, 41, 25, 20},
    };
    private static final int[] PERM1024 = {0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1};

    private final long[] ek;   // extended key: nw key words + parity word
    private final long[] et;   // extended tweak: t0, t1, t0 ^ t1
    private final int[][] rot;
    private final int[] perm;
    private final int rounds;
    private final int nw;
    /** The variant's block size in bytes (equal to the key and IV lengths). */
    public final int blockBytes;

    private Threefish(byte[] key, byte[] tweak, int nw, int rounds, int[][] rot, int[] perm) {
        this.nw = nw;
        this.rounds = rounds;
        this.rot = rot;
        this.perm = perm;
        this.blockBytes = nw * 8;
        if (key.length != blockBytes) {
            throw new IllegalArgumentException("key must be " + blockBytes + " bytes, got " + key.length);
        }
        if (tweak.length != 16) {
            throw new IllegalArgumentException("tweak must be 16 bytes, got " + tweak.length);
        }
        ek = new long[nw + 1];
        long parity = C240;
        for (int i = 0; i < nw; i++) {
            long w = le64(key, i * 8);
            ek[i] = w;
            parity ^= w;
        }
        ek[nw] = parity;
        long t0 = le64(tweak, 0);
        long t1 = le64(tweak, 8);
        et = new long[] {t0, t1, t0 ^ t1};
    }

    public static Threefish t256(byte[] key, byte[] tweak) {
        return new Threefish(key, tweak, 4, 72, ROT256, PERM256);
    }

    public static Threefish t512(byte[] key, byte[] tweak) {
        return new Threefish(key, tweak, 8, 72, ROT512, PERM512);
    }

    public static Threefish t1024(byte[] key, byte[] tweak) {
        return new Threefish(key, tweak, 16, 80, ROT1024, PERM1024);
    }

    private void addSubkey(long[] state, int s) {
        for (int i = 0; i < nw; i++) {
            long k = ek[(s + i) % (nw + 1)];
            if (i == nw - 3) {
                k += et[s % 3];
            } else if (i == nw - 2) {
                k += et[(s + 1) % 3];
            } else if (i == nw - 1) {
                k += s;
            }
            state[i] += k;
        }
    }

    private void subSubkey(long[] state, int s) {
        for (int i = 0; i < nw; i++) {
            long k = ek[(s + i) % (nw + 1)];
            if (i == nw - 3) {
                k += et[s % 3];
            } else if (i == nw - 2) {
                k += et[(s + 1) % 3];
            } else if (i == nw - 1) {
                k += s;
            }
            state[i] -= k;
        }
    }

    private void encryptState(long[] state) {
        long[] scratch = new long[nw];
        for (int r = 0; r < rounds; r++) {
            if (r % 4 == 0) {
                addSubkey(state, r / 4);
            }
            for (int j = 0; j < nw / 2; j++) {
                long x0 = state[2 * j];
                long x1 = state[2 * j + 1];
                long y0 = x0 + x1;
                long y1 = Long.rotateLeft(x1, rot[j][r % 8]) ^ y0;
                state[2 * j] = y0;
                state[2 * j + 1] = y1;
            }
            for (int i = 0; i < nw; i++) {
                scratch[i] = state[perm[i]];
            }
            System.arraycopy(scratch, 0, state, 0, nw);
        }
        addSubkey(state, rounds / 4);
    }

    private void decryptState(long[] state) {
        long[] scratch = new long[nw];
        subSubkey(state, rounds / 4);
        for (int r = rounds - 1; r >= 0; r--) {
            for (int i = 0; i < nw; i++) {
                scratch[perm[i]] = state[i];
            }
            System.arraycopy(scratch, 0, state, 0, nw);
            for (int j = 0; j < nw / 2; j++) {
                long y0 = state[2 * j];
                long y1 = state[2 * j + 1];
                long x1 = Long.rotateRight(y1 ^ y0, rot[j][r % 8]);
                long x0 = y0 - x1;
                state[2 * j] = x0;
                state[2 * j + 1] = x1;
            }
            if (r % 4 == 0) {
                subSubkey(state, r / 4);
            }
        }
    }

    /** Encrypt one block from src into dst (each {@code blockBytes} long). */
    public void encryptBlock(byte[] dst, byte[] src) {
        crypt(dst, src, true);
    }

    /** Decrypt one block from src into dst. */
    public void decryptBlock(byte[] dst, byte[] src) {
        crypt(dst, src, false);
    }

    private void crypt(byte[] dst, byte[] src, boolean encrypt) {
        long[] state = new long[nw];
        for (int i = 0; i < nw; i++) {
            state[i] = le64(src, i * 8);
        }
        if (encrypt) {
            encryptState(state);
        } else {
            decryptState(state);
        }
        for (int i = 0; i < nw; i++) {
            putLe64(dst, i * 8, state[i]);
        }
    }

    /**
     * A resumable CTR keystream. {@link #apply} may be called once per chunk, with
     * the counter carrying across calls, so a file can be encrypted chunk by chunk
     * in constant memory and stay identical to whole-file CTR (non-final chunks are
     * whole blocks, so the counter stays block-aligned at each boundary). The IV is
     * the initial counter, a big-endian integer incremented per block.
     */
    public final class Ctr {
        private final byte[] counter;
        private final byte[] ks = new byte[blockBytes];

        private Ctr(byte[] iv) {
            if (iv.length != blockBytes) {
                throw new IllegalArgumentException("iv must be " + blockBytes + " bytes, got " + iv.length);
            }
            this.counter = iv.clone();
        }

        /** XOR the keystream into {@code data[0..len)} (encrypt == decrypt). */
        public void apply(byte[] data, int len) {
            for (int off = 0; off < len; off += blockBytes) {
                encryptBlock(ks, counter);
                int n = Math.min(blockBytes, len - off);
                for (int j = 0; j < n; j++) {
                    data[off + j] ^= ks[j];
                }
                incrementBE(counter);
            }
        }
    }

    /** Start a CTR keystream from iv (the initial big-endian counter). */
    public Ctr newCtr(byte[] iv) {
        return new Ctr(iv);
    }

    /** Apply CTR over the whole buffer in place (encrypt == decrypt). */
    public void ctrApply(byte[] iv, byte[] data) {
        newCtr(iv).apply(data, data.length);
    }

    private static void incrementBE(byte[] c) {
        for (int i = c.length - 1; i >= 0; i--) {
            if (++c[i] != 0) {
                break;
            }
        }
    }

    /** Read 8 little-endian bytes at {@code off} as an unsigned 64-bit value. */
    static long le64(byte[] b, int off) {
        return (b[off] & 0xffL)
            | (b[off + 1] & 0xffL) << 8
            | (b[off + 2] & 0xffL) << 16
            | (b[off + 3] & 0xffL) << 24
            | (b[off + 4] & 0xffL) << 32
            | (b[off + 5] & 0xffL) << 40
            | (b[off + 6] & 0xffL) << 48
            | (b[off + 7] & 0xffL) << 56;
    }

    /** Write {@code v} as 8 little-endian bytes at {@code off}. */
    static void putLe64(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (8 * i));
        }
    }
}

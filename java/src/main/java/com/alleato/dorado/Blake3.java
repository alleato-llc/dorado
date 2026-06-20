package com.alleato.dorado;

/**
 * From-scratch BLAKE3 hash and keyed MAC, using the streaming chunk-stack
 * algorithm: input is split into 1024-byte chunks, each compressed to a chaining
 * value, and chaining values are merged pairwise into a Merkle tree up to a single
 * root, holding only fixed-size state. The inherent finalize is an
 * extendable-output function for any length. Java port of the dorado Rust crate's
 * blake3 module.
 */
public final class Blake3 {
    private static final int BLOCK_BYTES = 64;
    private static final int CHUNK_BYTES = 1024;

    private static final int CHUNK_START = 1 << 0;
    private static final int CHUNK_END = 1 << 1;
    private static final int FLAG_PARENT = 1 << 2;
    private static final int FLAG_ROOT = 1 << 3;
    private static final int KEYED_HASH = 1 << 4;

    private static final int[] IV = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    private static final int[] MSG_PERMUTATION = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};

    private Blake3() {}

    private static void g(int[] s, int a, int b, int c, int d, int mx, int my) {
        s[a] = s[a] + s[b] + mx;
        s[d] = Integer.rotateRight(s[d] ^ s[a], 16);
        s[c] = s[c] + s[d];
        s[b] = Integer.rotateRight(s[b] ^ s[c], 12);
        s[a] = s[a] + s[b] + my;
        s[d] = Integer.rotateRight(s[d] ^ s[a], 8);
        s[c] = s[c] + s[d];
        s[b] = Integer.rotateRight(s[b] ^ s[c], 7);
    }

    private static int[] compress(int[] cv, int[] block, long counter, int bLen, int flags) {
        int[] state = {
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
            IV[0], IV[1], IV[2], IV[3],
            (int) counter, (int) (counter >>> 32), bLen, flags,
        };
        int[] m = block.clone();
        for (int round = 0; round < 7; round++) {
            g(state, 0, 4, 8, 12, m[0], m[1]);
            g(state, 1, 5, 9, 13, m[2], m[3]);
            g(state, 2, 6, 10, 14, m[4], m[5]);
            g(state, 3, 7, 11, 15, m[6], m[7]);
            g(state, 0, 5, 10, 15, m[8], m[9]);
            g(state, 1, 6, 11, 12, m[10], m[11]);
            g(state, 2, 7, 8, 13, m[12], m[13]);
            g(state, 3, 4, 9, 14, m[14], m[15]);
            if (round < 6) {
                int[] permuted = new int[16];
                for (int i = 0; i < 16; i++) {
                    permuted[i] = m[MSG_PERMUTATION[i]];
                }
                m = permuted;
            }
        }
        for (int i = 0; i < 8; i++) {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }
        return state;
    }

    private static int[] wordsFromBlock(byte[] b, int len) {
        byte[] padded = new byte[BLOCK_BYTES];
        System.arraycopy(b, 0, padded, 0, len);
        int[] words = new int[16];
        for (int i = 0; i < 16; i++) {
            int o = i * 4;
            words[i] = (padded[o] & 0xff)
                | (padded[o + 1] & 0xff) << 8
                | (padded[o + 2] & 0xff) << 16
                | (padded[o + 3] & 0xff) << 24;
        }
        return words;
    }

    // A node's output: enough to produce a chaining value or root bytes.
    private static final class Output {
        final int[] inputCV;
        final int[] block;
        final long counter;
        final int bLen;
        final int flags;

        Output(int[] inputCV, int[] block, long counter, int bLen, int flags) {
            this.inputCV = inputCV;
            this.block = block;
            this.counter = counter;
            this.bLen = bLen;
            this.flags = flags;
        }

        int[] chainingValue() {
            int[] full = compress(inputCV, block, counter, bLen, flags);
            int[] cv = new int[8];
            System.arraycopy(full, 0, cv, 0, 8);
            return cv;
        }

        void rootOutputInto(byte[] out) {
            long ctr = 0;
            int written = 0;
            while (written < out.length) {
                int[] words = compress(inputCV, block, ctr, bLen, flags | FLAG_ROOT);
                for (int w : words) {
                    if (written >= out.length) {
                        break;
                    }
                    int n = Math.min(4, out.length - written);
                    for (int i = 0; i < n; i++) {
                        out[written + i] = (byte) (w >>> (8 * i));
                    }
                    written += n;
                }
                ctr++;
            }
        }
    }

    // Absorbs one chunk block by block in fixed-size state.
    private static final class ChunkState {
        int[] cv;
        final long chunkCounter;
        final byte[] block = new byte[BLOCK_BYTES];
        int blockLen;
        long blocksCompressed;
        final int flags;

        ChunkState(int[] key, long chunkCounter, int flags) {
            this.cv = key.clone();
            this.chunkCounter = chunkCounter;
            this.flags = flags;
        }

        int len() {
            return BLOCK_BYTES * (int) blocksCompressed + blockLen;
        }

        int startFlag() {
            return blocksCompressed == 0 ? CHUNK_START : 0;
        }

        void update(byte[] input, int off, int end) {
            while (off < end) {
                if (blockLen == BLOCK_BYTES) {
                    int[] bw = wordsFromBlock(block, BLOCK_BYTES);
                    int[] out = compress(cv, bw, chunkCounter, BLOCK_BYTES, flags | startFlag());
                    System.arraycopy(out, 0, cv, 0, 8);
                    blocksCompressed++;
                    java.util.Arrays.fill(block, (byte) 0);
                    blockLen = 0;
                }
                int take = Math.min(BLOCK_BYTES - blockLen, end - off);
                System.arraycopy(input, off, block, blockLen, take);
                blockLen += take;
                off += take;
            }
        }

        Output output() {
            return new Output(cv, wordsFromBlock(block, blockLen), chunkCounter, blockLen,
                flags | startFlag() | CHUNK_END);
        }
    }

    private static Output parentOutput(int[] left, int[] right, int[] key, int flags) {
        int[] block = new int[16];
        System.arraycopy(left, 0, block, 0, 8);
        System.arraycopy(right, 0, block, 8, 8);
        return new Output(key, block, 0, BLOCK_BYTES, flags | FLAG_PARENT);
    }

    private static int[] parentCV(int[] left, int[] right, int[] key, int flags) {
        return parentOutput(left, right, key, flags).chainingValue();
    }

    /** An incremental BLAKE3 hash/MAC (chunk-stack streaming). */
    public static final class Hasher {
        private ChunkState chunkState;
        private final int[] key;
        private final int[][] cvStack = new int[54][]; // max input 2^64 -> depth <= 54
        private int cvStackLen;
        private final int flags;

        private Hasher(int[] key, int flags) {
            this.key = key;
            this.flags = flags;
            this.chunkState = new ChunkState(key, 0, flags);
        }

        /** Start an unkeyed hash. */
        public static Hasher newHash() {
            return new Hasher(IV.clone(), 0);
        }

        /** Start a keyed MAC under a 32-byte key. */
        public static Hasher newKeyed(byte[] key32) {
            if (key32.length != 32) {
                throw new IllegalArgumentException("key must be 32 bytes");
            }
            int[] kw = new int[8];
            for (int i = 0; i < 8; i++) {
                int o = i * 4;
                kw[i] = (key32[o] & 0xff)
                    | (key32[o + 1] & 0xff) << 8
                    | (key32[o + 2] & 0xff) << 16
                    | (key32[o + 3] & 0xff) << 24;
            }
            return new Hasher(kw, KEYED_HASH);
        }

        private void pushStack(int[] cv) {
            cvStack[cvStackLen++] = cv;
        }

        private int[] popStack() {
            return cvStack[--cvStackLen];
        }

        private void addChunkCV(int[] newCV, long totalChunks) {
            while ((totalChunks & 1) == 0) {
                newCV = parentCV(popStack(), newCV, key, flags);
                totalChunks >>>= 1;
            }
            pushStack(newCV);
        }

        /** Feed input bytes. */
        public void update(byte[] input) {
            int off = 0;
            int end = input.length;
            while (off < end) {
                if (chunkState.len() == CHUNK_BYTES) {
                    int[] chunkCV = chunkState.output().chainingValue();
                    long totalChunks = chunkState.chunkCounter + 1;
                    addChunkCV(chunkCV, totalChunks);
                    chunkState = new ChunkState(key, totalChunks, flags);
                }
                int take = Math.min(CHUNK_BYTES - chunkState.len(), end - off);
                chunkState.update(input, off, off + take);
                off += take;
            }
        }

        /** Write the digest into out (any length; an XOF for len &gt; 32). */
        public void finalizeInto(byte[] out) {
            Output o = chunkState.output();
            int remaining = cvStackLen;
            while (remaining > 0) {
                remaining--;
                o = parentOutput(cvStack[remaining], o.chainingValue(), key, flags);
            }
            o.rootOutputInto(out);
        }
    }

    /** One-shot keyed BLAKE3 MAC: writes outLen bytes into a fresh array. */
    public static byte[] keyedMac(byte[] key32, int outLen, byte[] input) {
        Hasher h = Hasher.newKeyed(key32);
        h.update(input);
        byte[] out = new byte[outLen];
        h.finalizeInto(out);
        return out;
    }

    /** One-shot unkeyed BLAKE3 hash producing outLen bytes. */
    public static byte[] hash(int outLen, byte[] input) {
        Hasher h = Hasher.newHash();
        h.update(input);
        byte[] out = new byte[outLen];
        h.finalizeInto(out);
        return out;
    }
}

package com.alleato.dorado.engine;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * The on-disk container format (magic "DRDO", version 4; version 3 still read):
 * header marshalling and streaming parse. Matches the Rust/Go/TS ports
 * byte-for-byte. All multi-byte integers are big-endian. {@code u32} header fields
 * are held in {@code long} so the validation bounds (in {@link Kdf}) cannot be
 * bypassed by a hostile value with the high bit set.
 */
public final class Format {
    public static final String MAGIC = "DRDO";
    public static final int VERSION = 4;
    public static final int DEFAULT_CHUNK_BYTES = 64 * 1024;
    /** Hard ceiling on an accepted chunk size. The effective cap can only be lower. */
    public static final long MAX_CHUNK_BYTES = 1L << 30;
    /** Default accepted chunk-size cap when the environment does not override it. */
    public static final long DEFAULT_MAX_CHUNK_BYTES = 64L * 1024 * 1024;
    public static final int MAX_LABEL_LEN = 4096;
    public static final int MAC_KEY_LEN = 32;
    public static final int TAG_LEN = 32;

    // Variant codes.
    public static final int T256 = 0;
    public static final int T512 = 1;
    public static final int T1024 = 2;

    // MAC ids.
    public static final int MAC_HMAC = 1;
    public static final int MAC_SKEIN = 2;
    public static final int MAC_BLAKE3 = 3;

    // KDF ids.
    public static final int KDF_ARGON2ID = 1;
    public static final int KDF_SCRYPT = 2;
    public static final int KDF_PBKDF2 = 3;
    public static final int PRF_HMAC_SHA256 = 1;

    private Format() {}

    /**
     * The effective accepted chunk-size cap. Reads the {@code DORADO_MAX_CHUNK_BYTES}
     * environment variable and clamps it into {@code [1, MAX_CHUNK_BYTES]}; an unset,
     * empty, or unparseable value yields {@link #DEFAULT_MAX_CHUNK_BYTES}. The override
     * can only tighten the cap below the hard ceiling, never raise it past 1 GiB.
     */
    public static long maxChunkBytes() {
        return clampChunkCap(System.getenv("DORADO_MAX_CHUNK_BYTES"));
    }

    /**
     * Pure helper backing {@link #maxChunkBytes()}: maps a raw env-var string to an
     * effective chunk-size cap. {@code null}, empty, or non-parseable-as-a-non-negative
     * integer yields {@link #DEFAULT_MAX_CHUNK_BYTES}; a parsed value is clamped into
     * {@code [1, MAX_CHUNK_BYTES]}.
     */
    public static long clampChunkCap(String raw) {
        if (raw == null || raw.isEmpty()) {
            return DEFAULT_MAX_CHUNK_BYTES;
        }
        long v;
        try {
            v = Long.parseLong(raw.trim());
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_CHUNK_BYTES;
        }
        if (v < 0) {
            return DEFAULT_MAX_CHUNK_BYTES;
        }
        if (v < 1) {
            return 1;
        }
        return Math.min(v, MAX_CHUNK_BYTES);
    }

    /** The variant's key/block/IV length in bytes. */
    public static int keyLen(int variant) {
        return switch (variant) {
            case T256 -> 32;
            case T512 -> 64;
            case T1024 -> 128;
            default -> throw new IllegalArgumentException("unknown variant code " + variant);
        };
    }

    public static int blockLen(int variant) {
        return keyLen(variant);
    }

    /** A KDF choice with its cost parameters (only the fields for {@code kind} are used). */
    public static final class KdfParams {
        public final int kind;
        public long mCost;  // argon2id: memory in KiB
        public long tCost;  // argon2id: iterations
        public long pCost;  // argon2id: lanes
        public int logN;    // scrypt: log2(N)
        public long r;      // scrypt: block factor
        public long p;      // scrypt: parallelism
        public long rounds; // pbkdf2: iterations
        public int prf;     // pbkdf2: PRF id

        public KdfParams(int kind) {
            this.kind = kind;
        }

        public static KdfParams argon2id(long mCostKib, long tCost, long pCost) {
            KdfParams k = new KdfParams(KDF_ARGON2ID);
            k.mCost = mCostKib;
            k.tCost = tCost;
            k.pCost = pCost;
            return k;
        }

        public static KdfParams scrypt(int logN, long r, long p) {
            KdfParams k = new KdfParams(KDF_SCRYPT);
            k.logN = logN;
            k.r = r;
            k.p = p;
            return k;
        }

        public static KdfParams pbkdf2(long rounds) {
            KdfParams k = new KdfParams(KDF_PBKDF2);
            k.rounds = rounds;
            k.prf = PRF_HMAC_SHA256;
            return k;
        }
    }

    /** The non-secret header preceding the ciphertext in a password file. */
    public static final class Header {
        public int version;
        public int variant;
        public KdfParams kdf;
        public int mac;
        public long chunkSize;
        public byte[] salt;
        public byte[] tweak; // 16 bytes
        public byte[] iv;
        public byte[] label;
    }

    private static void putU16(ByteArrayOutputStream b, int v) {
        b.write((v >>> 8) & 0xff);
        b.write(v & 0xff);
    }

    private static void putU32(ByteArrayOutputStream b, long v) {
        b.write((int) ((v >>> 24) & 0xff));
        b.write((int) ((v >>> 16) & 0xff));
        b.write((int) ((v >>> 8) & 0xff));
        b.write((int) (v & 0xff));
    }

    /** Serialize a header to its on-disk bytes. */
    public static byte[] marshal(Header h) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(MAGIC.getBytes(US_ASCII));
        b.write(h.version);
        b.write(h.variant);
        switch (h.kdf.kind) {
            case KDF_ARGON2ID -> {
                b.write(1);
                putU32(b, h.kdf.mCost);
                putU32(b, h.kdf.tCost);
                putU32(b, h.kdf.pCost);
            }
            case KDF_SCRYPT -> {
                b.write(2);
                b.write(h.kdf.logN);
                putU32(b, h.kdf.r);
                putU32(b, h.kdf.p);
            }
            case KDF_PBKDF2 -> {
                b.write(3);
                putU32(b, h.kdf.rounds);
                b.write(h.kdf.prf);
            }
            default -> throw new IllegalArgumentException("unknown kdf kind " + h.kdf.kind);
        }
        b.write(h.mac);
        putU32(b, h.chunkSize);
        b.write(h.salt.length);
        b.writeBytes(h.salt);
        b.writeBytes(h.tweak);
        b.writeBytes(h.iv);
        if (h.version >= 4) {
            putU16(b, h.label.length);
            b.writeBytes(h.label);
        }
        return b.toByteArray();
    }

    private static byte[] readExact(InputStream in, int n, String what) throws IOException {
        byte[] b = in.readNBytes(n);
        if (b.length != n) {
            throw new DoradoException("header truncated reading " + what);
        }
        return b;
    }

    private static int readU8(InputStream in, String what) throws IOException {
        return readExact(in, 1, what)[0] & 0xff;
    }

    private static int readU16(InputStream in, String what) throws IOException {
        byte[] b = readExact(in, 2, what);
        return (b[0] & 0xff) << 8 | (b[1] & 0xff);
    }

    private static long readU32(InputStream in, String what) throws IOException {
        byte[] b = readExact(in, 4, what);
        return (b[0] & 0xffL) << 24 | (b[1] & 0xffL) << 16 | (b[2] & 0xffL) << 8 | (b[3] & 0xffL);
    }

    /** Read a header from in, leaving it positioned at the first frame. */
    public static Header read(InputStream in) throws IOException {
        byte[] m = readExact(in, 4, "magic");
        if (!new String(m, US_ASCII).equals(MAGIC)) {
            throw new DoradoException("not a dorado password file (bad magic)");
        }
        Header h = new Header();
        h.version = readU8(in, "version");
        if (h.version != 3 && h.version != VERSION) {
            throw new DoradoException("unsupported format version " + h.version);
        }
        h.variant = readU8(in, "variant");
        keyLen(h.variant); // validates the code

        int kdfId = readU8(in, "kdf id");
        KdfParams kdf;
        switch (kdfId) {
            case KDF_ARGON2ID -> {
                kdf = new KdfParams(KDF_ARGON2ID);
                kdf.mCost = readU32(in, "m_cost");
                kdf.tCost = readU32(in, "t_cost");
                kdf.pCost = readU32(in, "p_cost");
            }
            case KDF_SCRYPT -> {
                kdf = new KdfParams(KDF_SCRYPT);
                kdf.logN = readU8(in, "log_n");
                kdf.r = readU32(in, "r");
                kdf.p = readU32(in, "p");
            }
            case KDF_PBKDF2 -> {
                kdf = new KdfParams(KDF_PBKDF2);
                kdf.rounds = readU32(in, "rounds");
                int prf = readU8(in, "prf");
                if (prf != PRF_HMAC_SHA256) {
                    throw new DoradoException("unknown prf id " + prf);
                }
                kdf.prf = prf;
            }
            default -> throw new DoradoException("unknown kdf id " + kdfId);
        }
        h.kdf = kdf;

        h.mac = readU8(in, "mac id");
        if (h.mac < 1 || h.mac > 3) {
            throw new DoradoException("unknown mac id " + h.mac);
        }
        h.chunkSize = readU32(in, "chunk size");
        int saltLen = readU8(in, "salt len");
        h.salt = readExact(in, saltLen, "salt");
        h.tweak = readExact(in, 16, "tweak");
        h.iv = readExact(in, blockLen(h.variant), "iv");
        if (h.version >= 4) {
            int labelLen = readU16(in, "label len");
            if (labelLen > MAX_LABEL_LEN) {
                throw new DoradoException("label too long (" + labelLen + " bytes)");
            }
            h.label = readExact(in, labelLen, "label");
        } else {
            h.label = new byte[0];
        }
        return h;
    }
}

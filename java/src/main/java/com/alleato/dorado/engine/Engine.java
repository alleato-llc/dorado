package com.alleato.dorado.engine;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.alleato.dorado.Threefish;
import com.alleato.dorado.engine.Format.Header;
import com.alleato.dorado.engine.Format.KdfParams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The construction over the Threefish cipher: the authenticated chunked password
 * container, raw CTR, and inspect. Streaming over {@link InputStream}/{@link
 * OutputStream} in constant memory (files larger than RAM are fine), matching the
 * Rust reference and the Go port; {@code byte[]} convenience wrappers are provided.
 * The on-disk output is byte-for-byte identical to the other ports, so {@code .mahi}
 * files are cross-compatible.
 *
 * <p>This is an SDK (library) only; there is no CLI. Educational and unaudited.
 */
public final class Engine {
    private static final String FRAME_DOMAIN = "DRDOchnk";
    private static final SecureRandom RNG = new SecureRandom();
    private static final int RAW_BUF = 64 * 1024;

    private Engine() {}

    /** Options for password encryption. Decryption reads these from the header. */
    public static final class PasswordOptions {
        public int variant = Format.T256;
        public KdfParams kdf = KdfParams.argon2id(64 * 1024, 3, 1);
        public int mac = Format.MAC_SKEIN;
        public byte[] tweak = new byte[16];
        public int chunkSize = Format.DEFAULT_CHUNK_BYTES;
        public byte[] label = new byte[0];

        public PasswordOptions() {}
    }

    /** The non-secret description of a container's header. */
    public record ContainerInfo(
        int version, int variant, KdfParams kdf, int mac, long chunkSize, int saltLen, byte[] tweak, byte[] label) {}

    private static Threefish cipher(int v, byte[] key, byte[] tweak) {
        return switch (v) {
            case Format.T256 -> Threefish.t256(key, tweak);
            case Format.T512 -> Threefish.t512(key, tweak);
            case Format.T1024 -> Threefish.t1024(key, tweak);
            default -> throw new IllegalArgumentException("unknown variant " + v);
        };
    }

    private static void putU32(ByteArrayOutputStream b, long v) {
        b.write((int) ((v >>> 24) & 0xff));
        b.write((int) ((v >>> 16) & 0xff));
        b.write((int) ((v >>> 8) & 0xff));
        b.write((int) (v & 0xff));
    }

    private static void putU64(ByteArrayOutputStream b, long v) {
        for (int i = 7; i >= 0; i--) {
            b.write((int) ((v >>> (8 * i)) & 0xff));
        }
    }

    private static byte[] frameAAD(byte[] headerBytes, long index, boolean isLast, byte[] ct) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(FRAME_DOMAIN.getBytes(US_ASCII));
        if (index == 0) {
            b.writeBytes(headerBytes);
        }
        putU64(b, index);
        b.write(isLast ? 1 : 0);
        putU32(b, ct.length);
        b.writeBytes(ct);
        return b.toByteArray();
    }

    private static void writeFrame(OutputStream out, boolean isLast, byte[] ct, byte[] tag) throws IOException {
        byte[] head = new byte[5];
        head[0] = (byte) (isLast ? 1 : 0);
        head[1] = (byte) ((ct.length >>> 24) & 0xff);
        head[2] = (byte) ((ct.length >>> 16) & 0xff);
        head[3] = (byte) ((ct.length >>> 8) & 0xff);
        head[4] = (byte) (ct.length & 0xff);
        out.write(head);
        out.write(ct);
        out.write(tag);
    }

    /** Default options: Threefish-256, Argon2id, Skein-512 MAC, 64 KiB chunks. */
    public static PasswordOptions defaultOptions() {
        return new PasswordOptions();
    }

    // ---- streaming API ----

    /** Encrypt {@code in} into {@code out} as an authenticated password container. */
    public static void encryptPasswordStream(byte[] password, PasswordOptions opts, InputStream in, OutputStream out)
            throws IOException {
        if (opts.label.length > Format.MAX_LABEL_LEN) {
            throw new DoradoException("label too long (" + opts.label.length + " bytes)");
        }
        int v = opts.variant;
        int blockLen = Format.blockLen(v);
        if (opts.chunkSize <= 0 || opts.chunkSize > Format.maxChunkBytes() || opts.chunkSize % blockLen != 0) {
            throw new IllegalArgumentException("chunk size must be a positive multiple of " + blockLen);
        }
        byte[] salt = new byte[16];
        byte[] iv = new byte[blockLen];
        RNG.nextBytes(salt);
        RNG.nextBytes(iv);

        byte[] keymat = Kdf.derive(opts.kdf, password, salt, Format.keyLen(v) + Format.MAC_KEY_LEN);
        byte[] encKey = Arrays.copyOfRange(keymat, 0, Format.keyLen(v));
        byte[] macKey = Arrays.copyOfRange(keymat, Format.keyLen(v), keymat.length);

        Header h = new Header();
        h.version = Format.VERSION;
        h.variant = v;
        h.kdf = opts.kdf;
        h.mac = opts.mac;
        h.chunkSize = opts.chunkSize;
        h.salt = salt;
        h.tweak = opts.tweak.clone();
        h.iv = iv;
        h.label = opts.label.clone();
        byte[] headerBytes = Format.marshal(h);

        Threefish.Ctr ctr = cipher(v, encKey, opts.tweak).newCtr(iv);
        out.write(headerBytes);

        // Read one chunk ahead so each chunk knows whether it is the last.
        byte[] current = in.readNBytes(opts.chunkSize);
        long index = 0;
        while (true) {
            byte[] next = in.readNBytes(opts.chunkSize);
            boolean isLast = next.length == 0;
            byte[] chunk = current.clone();
            ctr.apply(chunk, chunk.length);
            byte[] tag = Mac.tag(opts.mac, macKey, frameAAD(headerBytes, index, isLast, chunk));
            writeFrame(out, isLast, chunk, tag);
            if (isLast) {
                break;
            }
            index++;
            current = next;
        }
    }

    private record Frame(boolean isLast, byte[] ct, byte[] tag) {}

    private static Frame readFrame(InputStream in, long chunkSize) throws IOException {
        byte[] head = in.readNBytes(5);
        if (head.length == 0) {
            throw new DoradoException("stream ended before the final chunk (truncated)");
        }
        if (head.length < 5) {
            throw new DoradoException("incomplete frame header (truncated)");
        }
        int flag = head[0] & 0xff;
        if (flag > 1) {
            throw new DoradoException("invalid frame flag " + flag);
        }
        boolean isLast = flag == 1;
        long ctLen = (head[1] & 0xffL) << 24 | (head[2] & 0xffL) << 16 | (head[3] & 0xffL) << 8 | (head[4] & 0xffL);
        if (ctLen > chunkSize) {
            throw new DoradoException("frame length exceeds the header chunk size");
        }
        byte[] ct = in.readNBytes((int) ctLen);
        if (ct.length != ctLen) {
            throw new DoradoException("truncated frame ciphertext");
        }
        byte[] tag = in.readNBytes(Format.TAG_LEN);
        if (tag.length != Format.TAG_LEN) {
            throw new DoradoException("truncated frame tag");
        }
        return new Frame(isLast, ct, tag);
    }

    /** Decrypt an authenticated password container from {@code in} into {@code out}. */
    public static void decryptPasswordStream(byte[] password, InputStream in, OutputStream out) throws IOException {
        decryptPasswordStream(password, null, in, out);
    }

    /**
     * Decrypt a container; if {@code expectedLabel} is non-null the container's label
     * must equal it, or decryption fails before any plaintext is written.
     */
    public static void decryptPasswordStream(byte[] password, byte[] expectedLabel, InputStream in, OutputStream out)
            throws IOException {
        Header h = Format.read(in);
        if (expectedLabel != null && !Arrays.equals(expectedLabel, h.label)) {
            throw new DoradoException("container label does not match the expected label");
        }
        byte[] headerBytes = Format.marshal(h);
        int blockLen = Format.blockLen(h.variant);
        if (h.chunkSize == 0 || h.chunkSize > Format.maxChunkBytes() || h.chunkSize % blockLen != 0) {
            throw new DoradoException("invalid chunk size " + h.chunkSize + " in header");
        }
        Kdf.validate(h.kdf);

        byte[] keymat = Kdf.derive(h.kdf, password, h.salt, Format.keyLen(h.variant) + Format.MAC_KEY_LEN);
        byte[] encKey = Arrays.copyOfRange(keymat, 0, Format.keyLen(h.variant));
        byte[] macKey = Arrays.copyOfRange(keymat, Format.keyLen(h.variant), keymat.length);

        Threefish.Ctr ctr = cipher(h.variant, encKey, h.tweak).newCtr(h.iv);
        long index = 0;
        while (true) {
            Frame fr = readFrame(in, h.chunkSize);
            if (!Mac.verify(h.mac, macKey, frameAAD(headerBytes, index, fr.isLast, fr.ct), fr.tag)) {
                throw new DoradoException("authentication failed (wrong password, corruption, or tampering)");
            }
            byte[] plain = fr.ct.clone();
            ctr.apply(plain, plain.length);
            out.write(plain);
            if (fr.isLast) {
                break;
            }
            if (fr.ct.length != h.chunkSize) {
                throw new DoradoException("non-final chunk is not full size");
            }
            index++;
        }
    }

    /** Apply bare, unauthenticated CTR with a user-supplied key and IV, streaming. */
    public static void rawCtrStream(int variant, byte[] key, byte[] tweak, byte[] iv, InputStream in, OutputStream out)
            throws IOException {
        int blockLen = Format.blockLen(variant);
        if (iv.length != blockLen) {
            throw new IllegalArgumentException("iv must be " + blockLen + " bytes, got " + iv.length);
        }
        Threefish.Ctr ctr = cipher(variant, key, tweak).newCtr(iv);
        int bufSize = (RAW_BUF / blockLen) * blockLen; // a whole number of blocks
        while (true) {
            byte[] buf = in.readNBytes(bufSize);
            if (buf.length == 0) {
                break;
            }
            ctr.apply(buf, buf.length);
            out.write(buf);
            if (buf.length < bufSize) {
                break; // end of input (a short read only happens at EOF)
            }
        }
    }

    /** Read and describe a container's header without decrypting it. */
    public static ContainerInfo inspect(InputStream in) throws IOException {
        Header h = Format.read(in);
        return new ContainerInfo(
            h.version, h.variant, h.kdf, h.mac, h.chunkSize, h.salt.length, h.tweak, h.label);
    }

    // ---- in-memory convenience wrappers ----

    /** Encrypt plaintext into a container (in memory). */
    public static byte[] encryptPassword(byte[] password, PasswordOptions opts, byte[] plaintext) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encryptPasswordStream(password, opts, new ByteArrayInputStream(plaintext), out);
        return out.toByteArray();
    }

    /** Decrypt a container (in memory). */
    public static byte[] decryptPassword(byte[] password, byte[] data) throws IOException {
        return decryptPassword(password, data, null);
    }

    /** Decrypt a container with an expected label (in memory). */
    public static byte[] decryptPassword(byte[] password, byte[] data, byte[] expectedLabel) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        decryptPasswordStream(password, expectedLabel, new ByteArrayInputStream(data), out);
        return out.toByteArray();
    }

    /** Read and describe a container's header (in memory). */
    public static ContainerInfo inspect(byte[] data) throws IOException {
        return inspect(new ByteArrayInputStream(data));
    }

    /** Apply bare CTR over a buffer (in memory). */
    public static byte[] rawCtr(int variant, byte[] key, byte[] tweak, byte[] iv, byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        rawCtrStream(variant, key, tweak, iv, new ByteArrayInputStream(data), out);
        return out.toByteArray();
    }
}

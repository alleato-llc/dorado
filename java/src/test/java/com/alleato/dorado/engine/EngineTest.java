package com.alleato.dorado.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.alleato.dorado.engine.Engine.PasswordOptions;
import com.alleato.dorado.engine.Format.KdfParams;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Construction tests: round-trips, every KDF/MAC/variant, and the security properties. */
class EngineTest {
    private static final byte[] PW = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

    private static final int[] VARIANTS = {Format.T256, Format.T512, Format.T1024};
    private static final int[] MACS = {Format.MAC_SKEIN, Format.MAC_HMAC, Format.MAC_BLAKE3};

    private static KdfParams[] kdfs() {
        return new KdfParams[] {
            KdfParams.argon2id(8 * 1024, 1, 1),
            KdfParams.scrypt(14, 8, 1),
            KdfParams.pbkdf2(20_000),
        };
    }

    private static PasswordOptions opts(int variant, KdfParams kdf, int mac) {
        PasswordOptions o = new PasswordOptions();
        o.variant = variant;
        o.kdf = kdf;
        o.mac = mac;
        return o;
    }

    @Test
    void roundTripEveryVariantKdfMac() throws Exception {
        byte[] plaintext = "the quick brown fox jumps over the lazy dog".getBytes();
        for (int variant : VARIANTS) {
            for (KdfParams kdf : kdfs()) {
                for (int mac : MACS) {
                    byte[] ct = Engine.encryptPassword(PW, opts(variant, kdf, mac), plaintext);
                    byte[] back = Engine.decryptPassword(PW, ct);
                    assertArrayEquals(plaintext, back, "variant=" + variant + " kdf=" + kdf.kind + " mac=" + mac);
                }
            }
        }
    }

    @Test
    void emptyPlaintextRoundTrip() throws Exception {
        byte[] ct = Engine.encryptPassword(PW, opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN), new byte[0]);
        assertArrayEquals(new byte[0], Engine.decryptPassword(PW, ct));
    }

    @Test
    void multiChunkRoundTrip() throws Exception {
        PasswordOptions o = opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN);
        o.chunkSize = 128; // many frames for a 5000-byte payload
        byte[] plaintext = new byte[5000];
        for (int i = 0; i < plaintext.length; i++) {
            plaintext[i] = (byte) (i * 7);
        }
        byte[] ct = Engine.encryptPassword(PW, o, plaintext);
        assertArrayEquals(plaintext, Engine.decryptPassword(PW, ct));
    }

    @Test
    void wrongPasswordRejected() throws Exception {
        byte[] ct = Engine.encryptPassword(PW, opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN), "secret".getBytes());
        assertThrows(DoradoException.class, () -> Engine.decryptPassword("wrong".getBytes(), ct));
    }

    @Test
    void tamperingRejected() throws Exception {
        byte[] ct = Engine.encryptPassword(PW, opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN), "secret".getBytes());
        ct[ct.length - 1] ^= 0x01; // flip a tag byte
        assertThrows(DoradoException.class, () -> Engine.decryptPassword(PW, ct));
    }

    @Test
    void truncationRejected() throws Exception {
        byte[] ct = Engine.encryptPassword(PW, opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN), "secret".getBytes());
        byte[] cut = java.util.Arrays.copyOfRange(ct, 0, ct.length - 8);
        assertThrows(DoradoException.class, () -> Engine.decryptPassword(PW, cut));
    }

    @Test
    void badMagicRejected() {
        assertThrows(DoradoException.class, () -> Engine.inspect(new byte[] {'X', 'X', 'X', 'X', 0, 0, 0, 0}));
    }

    @Test
    void labelBinding() throws Exception {
        PasswordOptions o = opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN);
        o.label = "demo-context".getBytes();
        byte[] ct = Engine.encryptPassword(PW, o, "payload".getBytes());

        assertArrayEquals("payload".getBytes(), Engine.decryptPassword(PW, ct, "demo-context".getBytes()));
        assertArrayEquals("payload".getBytes(), Engine.decryptPassword(PW, ct)); // no expected label decrypts regardless
        assertThrows(DoradoException.class, () -> Engine.decryptPassword(PW, ct, "other".getBytes()));
        assertArrayEquals("demo-context".getBytes(), Engine.inspect(ct).label());
    }

    @Test
    void inspectReportsHeader() throws Exception {
        PasswordOptions o = opts(Format.T512, KdfParams.scrypt(14, 8, 1), Format.MAC_BLAKE3);
        byte[] ct = Engine.encryptPassword(PW, o, "hi".getBytes());
        Engine.ContainerInfo info = Engine.inspect(ct);
        assertEquals(Format.VERSION, info.version());
        assertEquals(Format.T512, info.variant());
        assertEquals(Format.MAC_BLAKE3, info.mac());
        assertEquals(Format.KDF_SCRYPT, info.kdf().kind);
        assertEquals(Format.DEFAULT_CHUNK_BYTES, info.chunkSize());
    }

    @Test
    void hostileKdfCostRejected() throws Exception {
        // A container claiming a huge argon2 memory cost must be refused on decrypt.
        PasswordOptions o = opts(Format.T256, KdfParams.argon2id(8 * 1024, 1, 1), Format.MAC_SKEIN);
        byte[] ct = Engine.encryptPassword(PW, o, "x".getBytes());
        // Patch the header m_cost (offset: magic 4 + version 1 + variant 1 + kdfid 1 = 7) to 2^31.
        ct[7] = (byte) 0x80;
        ct[8] = 0;
        ct[9] = 0;
        ct[10] = 0;
        assertThrows(DoradoException.class, () -> Engine.decryptPassword(PW, ct));
    }

    @Test
    void streamingApi() throws Exception {
        byte[] plaintext = "streamed payload across the input".getBytes();
        ByteArrayOutputStream enc = new ByteArrayOutputStream();
        Engine.encryptPasswordStream(PW, opts(Format.T256, KdfParams.pbkdf2(20_000), Format.MAC_SKEIN),
            new ByteArrayInputStream(plaintext), enc);
        ByteArrayOutputStream dec = new ByteArrayOutputStream();
        Engine.decryptPasswordStream(PW, new ByteArrayInputStream(enc.toByteArray()), dec);
        assertArrayEquals(plaintext, dec.toByteArray());
    }

    @Test
    void rawCtrRoundTrip() throws Exception {
        byte[] key = new byte[32];
        byte[] iv = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) i;
            iv[i] = (byte) (255 - i);
        }
        byte[] tweak = new byte[16];
        byte[] data = "raw CTR, any length, no header".getBytes();
        byte[] ct = Engine.rawCtr(Format.T256, key, tweak, iv, data);
        assertArrayEquals(data, Engine.rawCtr(Format.T256, key, tweak, iv, ct));
    }
}

package com.alleato.dorado.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Cross-compatibility: decrypt {@code .mahi} fixtures produced by the Rust reference
 * implementation (the baseline), one per KDF/MAC/variant plus a labeled and a
 * multi-frame file. These are checked-in regression guards that the Java port stays
 * byte-compatible with the shared format. The reverse direction (the Rust/Go CLIs
 * decrypting Java's output) is verified during development.
 */
class CrossCompatTest {
    private static final byte[] PW = "pw-cross".getBytes(StandardCharsets.UTF_8);

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = CrossCompatTest.class.getResourceAsStream("/crosscompat/" + name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    private static void check(String file, String expected) throws IOException {
        assertArrayEquals(expected.getBytes(), Engine.decryptPassword(PW, fixture(file)), file);
    }

    @Test
    void argon2idSkein256() throws IOException {
        check("argon_skein_256.mahi", "rust argon+skein+256");
    }

    @Test
    void scryptHmac512() throws IOException {
        check("scrypt_hmac_512.mahi", "rust scrypt+hmac+512");
    }

    @Test
    void pbkdf2Blake3_1024() throws IOException {
        check("pbkdf2_blake3_1024.mahi", "rust pbkdf2+blake3+1024");
    }

    @Test
    void labeledFile() throws IOException {
        byte[] data = fixture("labeled.mahi");
        assertEquals("demo-context", new String(Engine.inspect(data).label(), StandardCharsets.UTF_8));
        assertArrayEquals("rust labeled payload".getBytes(), Engine.decryptPassword(PW, data, "demo-context".getBytes()));
        assertThrows(DoradoException.class, () -> Engine.decryptPassword(PW, data, "wrong".getBytes()));
    }

    @Test
    void multiFrameFile() throws IOException {
        byte[] plain = Engine.decryptPassword(PW, fixture("multichunk.mahi"));
        assertEquals(5000, plain.length);
        byte[] expected = new byte[5000];
        java.util.Arrays.fill(expected, (byte) 'x');
        assertArrayEquals(expected, plain);
    }
}

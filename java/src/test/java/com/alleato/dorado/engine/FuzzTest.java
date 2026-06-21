package com.alleato.dorado.engine;

import static org.junit.jupiter.api.Assertions.fail;

import com.alleato.dorado.engine.Engine.PasswordOptions;
import com.alleato.dorado.engine.Format.KdfParams;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Property test: feeding arbitrary, truncated, or mutated bytes to the decrypt and
 * inspect entry points must always either succeed or throw a declared, expected
 * exception. It must never throw an unexpected runtime error (NullPointerException,
 * ArrayIndexOutOfBoundsException, OutOfMemoryError, a generic RuntimeException) or
 * hang. The KDF cost bounds are enforced by the parser, so a malformed header can
 * never trigger an expensive derivation here.
 */
class FuzzTest {
    private static final byte[] PW = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

    /** Run one decrypt/inspect attempt and assert no unexpected throwable escapes. */
    private static void exercise(byte[] data) {
        attempt(() -> Engine.inspect(data));
        // Only attempt the (KDF-running) decrypt when the header is cheap to derive.
        // The parser, which is where a malformed input could crash, is fully covered
        // by inspect above; running a hostile-but-in-bounds KDF here would only burn
        // memory and time without exercising new container-handling code.
        if (cheapToDecrypt(data)) {
            attempt(() -> Engine.decryptPassword(PW, data));
            attempt(() -> Engine.decryptPassword(PW, data, "label".getBytes(StandardCharsets.UTF_8)));
        }
    }

    /** True if the header parses and its KDF parameters are small enough to run fast. */
    private static boolean cheapToDecrypt(byte[] data) {
        Engine.ContainerInfo info;
        try {
            info = Engine.inspect(data);
        } catch (Exception e) {
            // Unparseable header: decrypt will fail in the same parse step, cheaply.
            return true;
        }
        KdfParams k = info.kdf();
        return switch (k.kind) {
            case Format.KDF_ARGON2ID -> k.mCost <= 64 * 1024 && k.tCost <= 4 && k.pCost <= 4;
            case Format.KDF_SCRYPT -> k.logN <= 14 && k.r <= 8 && k.p <= 2;
            case Format.KDF_PBKDF2 -> k.rounds <= 100_000;
            default -> true;
        };
    }

    @FunctionalInterface
    private interface Call {
        void run() throws Exception;
    }

    private static void attempt(Call c) {
        try {
            c.run();
        } catch (IOException | IllegalArgumentException expected) {
            // The declared failure modes for a bad container: DoradoException and its
            // subtypes (a subtype of IOException), a real IOException, or a bad-parameter
            // IllegalArgumentException.
        } catch (Throwable t) {
            fail("unexpected throwable for fuzzed input: " + t.getClass().getName() + ": " + t.getMessage(), t);
        }
    }

    @Test
    void randomBytesNeverCrash() {
        Random rng = new Random(0xD0_0DAD0L);
        for (int i = 0; i < 4000; i++) {
            int len = rng.nextInt(512);
            byte[] data = new byte[len];
            rng.nextBytes(data);
            exercise(data);
        }
    }

    @Test
    void truncationsAndMutationsNeverCrash() throws Exception {
        // Start from a real container and feed every prefix plus single-byte mutations.
        PasswordOptions o = new PasswordOptions();
        o.variant = Format.T256;
        o.kdf = KdfParams.pbkdf2(20_000);
        o.mac = Format.MAC_SKEIN;
        o.chunkSize = 128;
        byte[] plaintext = new byte[600];
        new Random(1).nextBytes(plaintext);
        byte[] container = Engine.encryptPassword(PW, o, plaintext);

        // Every truncation prefix.
        for (int len = 0; len <= container.length; len++) {
            exercise(java.util.Arrays.copyOfRange(container, 0, len));
        }

        // Single-byte mutations seeded deterministically.
        Random rng = new Random(424242);
        for (int i = 0; i < 4000; i++) {
            byte[] m = container.clone();
            int pos = rng.nextInt(m.length);
            m[pos] ^= (byte) (1 + rng.nextInt(255));
            exercise(m);
        }
    }
}

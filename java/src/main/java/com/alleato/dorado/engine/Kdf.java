package com.alleato.dorado.engine;

import com.alleato.dorado.engine.Format.KdfParams;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * The three key-derivation functions. Argon2id, scrypt, and PBKDF2-HMAC-SHA256 are
 * delegated to Bouncy Castle (matching the other ports' use of a KDF library), so
 * the derived keys match the Rust/Go/TS ports byte-for-byte. The raw password bytes
 * are fed directly (PBKDF2 via {@code PKCS5S2ParametersGenerator}, not the JDK's
 * char[]-based API), which is what the other ports do.
 */
public final class Kdf {
    private Kdf() {}

    /** Stretch password (with salt) into outLen key bytes using params. */
    public static byte[] derive(KdfParams p, byte[] password, byte[] salt, int outLen) {
        return switch (p.kind) {
            case Format.KDF_ARGON2ID -> argon2id(password, salt, p, outLen);
            case Format.KDF_SCRYPT -> SCrypt.generate(password, salt, 1 << p.logN, (int) p.r, (int) p.p, outLen);
            case Format.KDF_PBKDF2 -> pbkdf2(password, salt, (int) p.rounds, outLen);
            default -> throw new IllegalArgumentException("unknown kdf kind " + p.kind);
        };
    }

    private static byte[] argon2id(byte[] password, byte[] salt, KdfParams p, int outLen) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations((int) p.tCost)
            .withMemoryAsKB((int) p.mCost)
            .withParallelism((int) p.pCost)
            .withSalt(salt)
            .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[outLen];
        gen.generateBytes(password, out);
        return out;
    }

    private static byte[] pbkdf2(byte[] password, byte[] salt, int rounds, int outLen) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password, salt, rounds);
        KeyParameter key = (KeyParameter) gen.generateDerivedParameters(outLen * 8);
        return key.getKey();
    }

    /**
     * Reject KDF parameters whose cost is unreasonably large. The cost comes from an
     * untrusted header, so without this a crafted file could request gigabytes of
     * memory or a multi-minute derivation. Bounds match the other ports.
     */
    public static void validate(KdfParams p) throws DoradoException {
        switch (p.kind) {
            case Format.KDF_ARGON2ID -> {
                if (p.mCost > (1L << 21)) {
                    throw new MalformedContainerException("argon2 memory cost too large");
                }
                if (p.tCost > 64) {
                    throw new MalformedContainerException("argon2 time cost too large");
                }
                if (p.pCost > 16) {
                    throw new MalformedContainerException("argon2 parallelism too large");
                }
            }
            case Format.KDF_SCRYPT -> {
                if (p.logN > 21) {
                    throw new MalformedContainerException("scrypt cost (log2 N) too large");
                }
                if (p.r > 32) {
                    throw new MalformedContainerException("scrypt block factor r too large");
                }
                if (p.p > 16) {
                    throw new MalformedContainerException("scrypt parallelism p too large");
                }
            }
            case Format.KDF_PBKDF2 -> {
                if (p.rounds > 50_000_000L) {
                    throw new MalformedContainerException("pbkdf2 rounds too large");
                }
            }
            default -> throw new MalformedContainerException("unknown kdf kind " + p.kind);
        }
    }
}

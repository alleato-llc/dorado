package com.alleato.dorado.engine;

import com.alleato.dorado.Blake3;
import com.alleato.dorado.Skein;
import com.alleato.dorado.engine.Format.KdfParams;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Key derivation, in its two standard forms.
 *
 * <p>{@link #deriveFromPassword} is password-based derivation (a PBKDF): it stretches
 * a weak, guessable secret into a raw key, deliberately slowly, under caller-tunable
 * cost parameters ({@link #validate} bounds untrusted ones). Argon2id, scrypt, and
 * PBKDF2-HMAC-SHA256 are delegated to Bouncy Castle (matching the other ports' use of
 * a KDF library), so the derived keys match the Rust/Go/TS ports byte-for-byte. The
 * raw password bytes are fed directly (PBKDF2 via {@code PKCS5S2ParametersGenerator},
 * not the JDK's char[]-based API), which is what the other ports do.
 *
 * <p>{@link #deriveFromKey} is key-based derivation (a KBKDF): it splits an already
 * high-entropy key into independent, domain-separated children, fast (one keyed
 * hash), with no salt and no cost parameters because there is nothing to stretch. The
 * keyed hash defaults to Skein-512 (Threefish's native companion);
 * {@link #deriveFromKeyWith} lets a caller pick the PRF ({@link KdfPrf}) instead, e.g.
 * BLAKE3 to keep a ChaCha-family construction single-family top to bottom. Both use
 * this port's from-scratch hashes, not Bouncy Castle. The names are the guardrail: a
 * password must never take the fast path, and a key never needs the slow one.
 */
public final class Kdf {
    private Kdf() {}

    /**
     * Stretch password (with salt) into outLen key bytes using params: password-based
     * derivation, deliberately slow (the cost is what an attacker pays per guess). For
     * deriving from an already-strong key, use {@link #deriveFromKey} instead.
     */
    public static byte[] deriveFromPassword(KdfParams p, byte[] password, byte[] salt, int outLen) {
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
     * The keyed hash {@link #deriveFromKeyWith} fans a master key out with. Both are
     * secure PRFs and produce identically strong children; the choice exists only to
     * let a construction stay within one cryptographic family (Skein for Threefish,
     * BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
     */
    public enum KdfPrf {
        /**
         * Skein-512 keyed hash (Threefish's native companion). The default, and what
         * {@link #deriveFromKey} uses. Accepts a key of any length.
         */
        SKEIN512,
        /**
         * BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's keyed mode is defined
         * only for a 256-bit key); other lengths throw {@link IllegalArgumentException}.
         */
        BLAKE3,
    }

    /**
     * Fixed prefix domain-separating {@link #deriveFromKey}'s keyed hashing from every
     * other keyed use in the engine ({@code DRDOrawE}/{@code DRDOrawM} in the raw-key
     * split, {@code DRDOchnk}/{@code DRDOrwFr} in the frame MACs).
     */
    private static final byte[] DERIVE_FROM_KEY_DOMAIN = "DRDOkdrv".getBytes(StandardCharsets.US_ASCII);

    /**
     * Derive outLen key bytes from an already high-entropy key, separated by domain:
     * key-based derivation, the fast form. One domain-separated Skein-512 keyed hash,
     * no salt, no cost parameters, because a strong key has nothing to stretch.
     * Deterministic: the same key and domain always yield the same bytes, and
     * different domains yield computationally unrelated ones, so a caller can fan one
     * master key out into independent per-purpose keys
     * ({@code deriveFromKey(master, "myapp/index", 32)},
     * {@code deriveFromKey(master, "myapp/data", 32)}). Never pass a password here:
     * there is no stretching, so a guessable input stays guessable; that is
     * {@link #deriveFromPassword}'s job. To fan out with a different PRF (e.g. BLAKE3),
     * use {@link #deriveFromKeyWith}.
     */
    public static byte[] deriveFromKey(byte[] key, String domain, int outLen) {
        return deriveFromKeyWith(KdfPrf.SKEIN512, key, domain, outLen);
    }

    /**
     * {@link #deriveFromKey} with a caller-chosen PRF ({@link KdfPrf}). The domain
     * separation, determinism, and "never pass a password" contract are exactly the
     * same; only the underlying keyed hash changes. With {@link KdfPrf#SKEIN512} this
     * is byte-for-byte identical to {@link #deriveFromKey}. {@link KdfPrf#BLAKE3}
     * requires key to be 32 bytes.
     */
    public static byte[] deriveFromKeyWith(KdfPrf prf, byte[] key, String domain, int outLen) {
        byte[] domainBytes = domain.getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[DERIVE_FROM_KEY_DOMAIN.length + domainBytes.length];
        System.arraycopy(DERIVE_FROM_KEY_DOMAIN, 0, msg, 0, DERIVE_FROM_KEY_DOMAIN.length);
        System.arraycopy(domainBytes, 0, msg, DERIVE_FROM_KEY_DOMAIN.length, domainBytes.length);
        return switch (prf) {
            case SKEIN512 -> Skein.mac(key, outLen, msg);
            case BLAKE3 -> {
                if (key.length != 32) {
                    throw new IllegalArgumentException("deriveFromKeyWith(BLAKE3) requires a 32-byte key");
                }
                yield Blake3.keyedMac(key, outLen, msg);
            }
        };
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
                if (p.rounds == 0) {
                    // Zero rounds would "derive" an all-zero key without error.
                    throw new MalformedContainerException("pbkdf2 rounds must be nonzero");
                }
                if (p.rounds > 50_000_000L) {
                    throw new MalformedContainerException("pbkdf2 rounds too large");
                }
            }
            default -> throw new MalformedContainerException("unknown kdf kind " + p.kind);
        }
    }
}

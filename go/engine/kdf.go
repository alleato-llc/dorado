package engine

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"

	"github.com/alleato-llc/dorado/go/blake3"
	"github.com/alleato-llc/dorado/go/skein"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// Key derivation, in its two standard forms.
//
// DeriveFromPassword is password-based derivation (a PBKDF): it stretches a
// weak, guessable secret into a raw key, deliberately slowly, under
// caller-tunable cost parameters (validate bounds untrusted ones).
// DeriveFromKey is key-based derivation (a KBKDF): it splits an already
// high-entropy key into independent, domain-separated children, fast (one
// keyed hash), with no salt and no cost parameters because there is nothing
// to stretch. The names are the guardrail: a password must never take the
// fast path, and a key never needs the slow one.

// DeriveFromPassword stretches password (with salt) into outLen key bytes
// using params -- password-based derivation, deliberately slow (the cost is
// what an attacker pays per guess). For deriving from an already-strong key,
// use DeriveFromKey instead. Argon2/scrypt come from golang.org/x/crypto
// (matching the Rust crate's use of the RustCrypto crates); PBKDF2 from the
// standard library. All are standard algorithms, so the outputs match the
// Rust side byte-for-byte.
func DeriveFromPassword(p KDFParams, password, salt []byte, outLen int) ([]byte, error) {
	switch p.Kind {
	case Argon2id:
		return argon2.IDKey(password, salt, p.TCost, p.MCost, uint8(p.PCost), uint32(outLen)), nil
	case Scrypt:
		return scrypt.Key(password, salt, 1<<p.LogN, int(p.R), int(p.P), outLen)
	case Pbkdf2:
		return pbkdf2.Key(sha256.New, string(password), salt, int(p.Rounds), outLen)
	}
	return nil, fmt.Errorf("%w: unknown kdf kind %d", ErrInvalidParams, p.Kind)
}

// KDFPrf selects the keyed hash DeriveFromKeyWith fans a master key out with.
// Both are secure PRFs and produce identically strong children; the choice
// exists only to let a construction stay within one cryptographic family
// (Skein for Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing
// lineages.
type KDFPrf byte

const (
	// KDFPrfSkein512 is the Skein-512 keyed hash (Threefish's native
	// companion). The default, and what DeriveFromKey uses. Accepts a key of
	// any length.
	KDFPrfSkein512 KDFPrf = iota
	// KDFPrfBLAKE3 is the BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's
	// keyed mode is defined only for a 256-bit key); other lengths panic.
	KDFPrfBLAKE3
)

// deriveFromKeyDomain is the fixed prefix domain-separating DeriveFromKey's
// keyed hashing from every other keyed use in the engine (DRDOrawE/DRDOrawM
// in the raw-key split, DRDOchnk/DRDOrwFr in the frame MACs).
const deriveFromKeyDomain = "DRDOkdrv"

// DeriveFromKey derives len(out) key bytes from an already high-entropy key,
// separated by domain -- key-based derivation (the fast form): one
// domain-separated Skein-512 keyed hash, no salt, no cost parameters, because
// a strong key has nothing to stretch. Deterministic: the same key and domain
// always yield the same bytes, and different domains yield computationally
// unrelated ones, so a caller can fan one master key out into independent
// per-purpose keys (DeriveFromKey(master, "myapp/index", ..),
// DeriveFromKey(master, "myapp/data", ..)). Never pass a password here: there
// is no stretching, so a guessable input stays guessable -- that is
// DeriveFromPassword's job. To fan out with a different PRF (e.g. BLAKE3),
// use DeriveFromKeyWith.
func DeriveFromKey(key []byte, domain string, out []byte) {
	DeriveFromKeyWith(KDFPrfSkein512, key, domain, out)
}

// DeriveFromKeyWith is DeriveFromKey with a caller-chosen PRF (KDFPrf). The
// domain separation, determinism, and "never pass a password" contract are
// exactly the same; only the underlying keyed hash changes. With
// KDFPrfSkein512 this is byte-for-byte identical to DeriveFromKey.
// KDFPrfBLAKE3 requires key to be 32 bytes and panics otherwise (a programmer
// error, like an invalid IV length in crypto/cipher).
func DeriveFromKeyWith(prf KDFPrf, key []byte, domain string, out []byte) {
	// One message, PRF(key, "DRDOkdrv" || domain), matching the Rust
	// reference and docs/fixtures/derive-from-key.md.
	msg := make([]byte, 0, len(deriveFromKeyDomain)+len(domain))
	msg = append(msg, deriveFromKeyDomain...)
	msg = append(msg, domain...)
	switch prf {
	case KDFPrfSkein512:
		copy(out, skein.MAC(key, len(out), msg))
	case KDFPrfBLAKE3:
		if len(key) != 32 {
			panic("engine: DeriveFromKeyWith(KDFPrfBLAKE3) requires a 32-byte key")
		}
		var k [32]byte
		copy(k[:], key)
		blake3.KeyedMAC(&k, out, msg)
	default:
		panic(fmt.Sprintf("engine: unknown KDFPrf %d", prf))
	}
}

// validate rejects KDF parameters whose cost is unreasonably large. The cost
// comes from an untrusted header, so without this a crafted file could request
// gigabytes of memory or a multi-minute derivation.
func validate(p KDFParams) error {
	switch p.Kind {
	case Argon2id:
		if p.MCost > 1<<21 {
			return fmt.Errorf("%w: argon2 memory cost too large", ErrInvalidParams)
		}
		if p.TCost > 64 {
			return fmt.Errorf("%w: argon2 time cost too large", ErrInvalidParams)
		}
		if p.PCost > 16 {
			return fmt.Errorf("%w: argon2 parallelism too large", ErrInvalidParams)
		}
	case Scrypt:
		if p.LogN > 21 {
			return fmt.Errorf("%w: scrypt cost (log2 N) too large", ErrInvalidParams)
		}
		if p.R > 32 {
			return fmt.Errorf("%w: scrypt block factor r too large", ErrInvalidParams)
		}
		if p.P > 16 {
			return fmt.Errorf("%w: scrypt parallelism p too large", ErrInvalidParams)
		}
	case Pbkdf2:
		if p.Rounds == 0 {
			// Zero rounds would "derive" an all-zero key without error.
			return fmt.Errorf("%w: pbkdf2 rounds must be nonzero", ErrInvalidParams)
		}
		if p.Rounds > 50_000_000 {
			return fmt.Errorf("%w: pbkdf2 rounds too large", ErrInvalidParams)
		}
	}
	return nil
}

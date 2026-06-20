package engine

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

// derive stretches password (with salt) into outLen key bytes using params.
// Argon2/scrypt come from golang.org/x/crypto (matching the Rust crate's use of
// the RustCrypto crates); PBKDF2 from the standard library. All are standard
// algorithms, so the outputs match the Rust side byte-for-byte.
func derive(p KDFParams, password, salt []byte, outLen int) ([]byte, error) {
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
		if p.Rounds > 50_000_000 {
			return fmt.Errorf("%w: pbkdf2 rounds too large", ErrInvalidParams)
		}
	}
	return nil
}

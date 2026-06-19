// Package engine is the construction over the Threefish cipher, shared by the
// CLIs: the KDFs, the authenticated chunked password container, raw CTR, and the
// MAC menu. It is the Go port of the dorado-engine Rust crate, and the on-disk
// format matches byte-for-byte (container version 4; version 3 is still read).
package engine

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic             = "DRDO"
	formatVersion     = 4
	defaultChunkBytes = 64 * 1024
	maxChunkBytes     = 1 << 30
	maxLabelLen       = 4096
	macKeyLen         = 32
	tagLen            = 32
)

// Variant selects the Threefish block size. The code byte is stored in the
// header and also fixes the key and IV lengths.
type Variant byte

const (
	T256  Variant = 0
	T512  Variant = 1
	T1024 Variant = 2
)

// KeyLen is the variant's key/block/IV length in bytes.
func (v Variant) KeyLen() int {
	switch v {
	case T256:
		return 32
	case T512:
		return 64
	case T1024:
		return 128
	}
	return 0
}

// BlockLen equals KeyLen.
func (v Variant) BlockLen() int { return v.KeyLen() }

func variantFromCode(b byte) (Variant, error) {
	if b > 2 {
		return 0, fmt.Errorf("unknown variant code %d", b)
	}
	return Variant(b), nil
}

// MacID selects the MAC that authenticates each chunk.
type MacID byte

const (
	MacHMAC   MacID = 1 // HMAC-SHA256
	MacSkein  MacID = 2 // Skein-512 (default)
	MacBLAKE3 MacID = 3 // keyed BLAKE3
)

func macFromCode(b byte) (MacID, error) {
	if b < 1 || b > 3 {
		return 0, fmt.Errorf("unknown mac id %d", b)
	}
	return MacID(b), nil
}

// PrfID is the PBKDF2 PRF.
type PrfID byte

const PrfHMACSHA256 PrfID = 1

// KDFKind selects the key-derivation function.
type KDFKind byte

const (
	Argon2id KDFKind = 1
	Scrypt   KDFKind = 2
	Pbkdf2   KDFKind = 3
)

// KDFParams is a KDF choice with its cost parameters (a flat struct; only the
// fields for Kind are used). This is exactly what the header stores.
type KDFParams struct {
	Kind KDFKind

	MCost, TCost, PCost uint32 // argon2id: memory KiB, iterations, lanes
	LogN                uint8  // scrypt: log2(N)
	R, P                uint32 // scrypt: block factor, parallelism
	Rounds              uint32 // pbkdf2: iterations
	Prf                 PrfID  // pbkdf2: PRF
}

// Header is the non-secret header preceding the ciphertext in a password file.
type Header struct {
	Version   byte
	Variant   Variant
	KDF       KDFParams
	Mac       MacID
	ChunkSize uint32
	Salt      []byte
	Tweak     [16]byte
	IV        []byte
	Label     []byte
}

func appendU16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }
func appendU32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// marshal serializes the header to its on-disk bytes.
func (h *Header) marshal() []byte {
	b := []byte(magic)
	b = append(b, h.Version, byte(h.Variant))
	switch h.KDF.Kind {
	case Argon2id:
		b = append(b, 1)
		b = appendU32(b, h.KDF.MCost)
		b = appendU32(b, h.KDF.TCost)
		b = appendU32(b, h.KDF.PCost)
	case Scrypt:
		b = append(b, 2, h.KDF.LogN)
		b = appendU32(b, h.KDF.R)
		b = appendU32(b, h.KDF.P)
	case Pbkdf2:
		b = append(b, 3)
		b = appendU32(b, h.KDF.Rounds)
		b = append(b, byte(h.KDF.Prf))
	}
	b = append(b, byte(h.Mac))
	b = appendU32(b, h.ChunkSize)
	b = append(b, byte(len(h.Salt)))
	b = append(b, h.Salt...)
	b = append(b, h.Tweak[:]...)
	b = append(b, h.IV...)
	if h.Version >= 4 {
		b = appendU16(b, uint16(len(h.Label)))
		b = append(b, h.Label...)
	}
	return b
}

func readN(r io.Reader, n int, what string) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("header truncated reading %s", what)
	}
	return buf, nil
}

func readByte(r io.Reader, what string) (byte, error) {
	b, err := readN(r, 1, what)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func readU16(r io.Reader, what string) (uint16, error) {
	b, err := readN(r, 2, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func readU32(r io.Reader, what string) (uint32, error) {
	b, err := readN(r, 4, what)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// readHeader parses a header from r, leaving it positioned at the first frame.
func readHeader(r io.Reader) (*Header, error) {
	m, err := readN(r, 4, "magic")
	if err != nil {
		return nil, err
	}
	if string(m) != magic {
		return nil, errors.New("not a dorado password file (bad magic)")
	}
	version, err := readByte(r, "version")
	if err != nil {
		return nil, err
	}
	if version != 3 && version != formatVersion {
		return nil, fmt.Errorf("unsupported format version %d", version)
	}
	vc, err := readByte(r, "variant")
	if err != nil {
		return nil, err
	}
	variant, err := variantFromCode(vc)
	if err != nil {
		return nil, err
	}

	kdfID, err := readByte(r, "kdf id")
	if err != nil {
		return nil, err
	}
	var kdf KDFParams
	switch kdfID {
	case 1:
		kdf.Kind = Argon2id
		if kdf.MCost, err = readU32(r, "m_cost"); err != nil {
			return nil, err
		}
		if kdf.TCost, err = readU32(r, "t_cost"); err != nil {
			return nil, err
		}
		if kdf.PCost, err = readU32(r, "p_cost"); err != nil {
			return nil, err
		}
	case 2:
		kdf.Kind = Scrypt
		if kdf.LogN, err = readByte(r, "log_n"); err != nil {
			return nil, err
		}
		if kdf.R, err = readU32(r, "r"); err != nil {
			return nil, err
		}
		if kdf.P, err = readU32(r, "p"); err != nil {
			return nil, err
		}
	case 3:
		kdf.Kind = Pbkdf2
		if kdf.Rounds, err = readU32(r, "rounds"); err != nil {
			return nil, err
		}
		prf, err := readByte(r, "prf")
		if err != nil {
			return nil, err
		}
		if prf != byte(PrfHMACSHA256) {
			return nil, fmt.Errorf("unknown prf id %d", prf)
		}
		kdf.Prf = PrfID(prf)
	default:
		return nil, fmt.Errorf("unknown kdf id %d", kdfID)
	}

	macByte, err := readByte(r, "mac id")
	if err != nil {
		return nil, err
	}
	mac, err := macFromCode(macByte)
	if err != nil {
		return nil, err
	}
	chunkSize, err := readU32(r, "chunk size")
	if err != nil {
		return nil, err
	}
	saltLen, err := readByte(r, "salt len")
	if err != nil {
		return nil, err
	}
	salt, err := readN(r, int(saltLen), "salt")
	if err != nil {
		return nil, err
	}
	tw, err := readN(r, 16, "tweak")
	if err != nil {
		return nil, err
	}
	iv, err := readN(r, variant.BlockLen(), "iv")
	if err != nil {
		return nil, err
	}
	var label []byte
	if version >= 4 {
		labelLen, err := readU16(r, "label len")
		if err != nil {
			return nil, err
		}
		if int(labelLen) > maxLabelLen {
			return nil, fmt.Errorf("label too long (%d bytes)", labelLen)
		}
		if label, err = readN(r, int(labelLen), "label"); err != nil {
			return nil, err
		}
	}

	h := &Header{
		Version:   version,
		Variant:   variant,
		KDF:       kdf,
		Mac:       mac,
		ChunkSize: chunkSize,
		Salt:      salt,
		IV:        iv,
		Label:     label,
	}
	copy(h.Tweak[:], tw)
	return h, nil
}

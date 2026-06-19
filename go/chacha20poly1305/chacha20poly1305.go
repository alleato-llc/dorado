// Package chacha20poly1305 is a from-scratch ChaCha20-Poly1305 AEAD (RFC 8439,
// section 2.8), built from the chacha and poly1305 packages and verified against
// the RFC test vector.
//
// The *InPlace functions are allocation-free (they transform the caller's buffer
// and feed Poly1305 incrementally). New returns a value implementing the
// standard library crypto/cipher.AEAD interface, which appends the tag to the
// ciphertext in the usual way. This is the Go port of the dorado Rust crate.
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/alleato-llc/dorado/go/chacha"
	"github.com/alleato-llc/dorado/go/poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

// ErrOpen is returned when authentication fails (wrong key, AAD, or tampering).
var ErrOpen = errors.New("chacha20poly1305: message authentication failed")

// polyKey derives the one-time Poly1305 key (keystream block 0).
func polyKey(key *[32]byte, nonce *[12]byte) [32]byte {
	blk := chacha.Block(key, 0, nonce)
	var k [32]byte
	copy(k[:], blk[:32])
	return k
}

// computeTag authenticates aad and ciphertext the RFC way: aad || pad16 ||
// ciphertext || pad16 || len(aad) || len(ciphertext), fed incrementally so
// nothing is assembled in memory.
func computeTag(otk *[32]byte, aad, ciphertext []byte) [16]byte {
	var zeros [16]byte
	p := poly1305.New(otk)
	p.Update(aad)
	p.Update(zeros[:(16-len(aad)%16)%16])
	p.Update(ciphertext)
	p.Update(zeros[:(16-len(ciphertext)%16)%16])
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ciphertext)))
	p.Update(lens[:])
	return p.Finalize()
}

// SealInPlace encrypts and authenticates in place: buf holds the plaintext on
// entry and the ciphertext on return; the tag is returned. Allocation-free.
func SealInPlace(key *[32]byte, nonce *[12]byte, aad, buf []byte) [16]byte {
	otk := polyKey(key, nonce)
	chacha.Apply(key, 1, nonce, buf)
	return computeTag(&otk, aad, buf)
}

// OpenInPlace verifies and decrypts in place: buf holds the ciphertext on entry
// and, on success, the plaintext on return. Returns ErrOpen (leaving buf
// unchanged) if the tag does not match. Allocation-free.
func OpenInPlace(key *[32]byte, nonce *[12]byte, aad, buf, tag []byte) error {
	otk := polyKey(key, nonce)
	expected := computeTag(&otk, aad, buf)
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return ErrOpen
	}
	chacha.Apply(key, 1, nonce, buf)
	return nil
}

// Seal encrypts and authenticates, returning the ciphertext and tag.
func Seal(key *[32]byte, nonce *[12]byte, aad, plaintext []byte) (ciphertext []byte, tag [16]byte) {
	buf := append([]byte(nil), plaintext...)
	tag = SealInPlace(key, nonce, aad, buf)
	return buf, tag
}

// Open verifies and decrypts, returning the plaintext or ErrOpen.
func Open(key *[32]byte, nonce *[12]byte, aad, ciphertext, tag []byte) ([]byte, error) {
	buf := append([]byte(nil), ciphertext...)
	if err := OpenInPlace(key, nonce, aad, buf, tag); err != nil {
		return nil, err
	}
	return buf, nil
}

// aead adapts the package to the standard library crypto/cipher.AEAD interface,
// appending the tag to the ciphertext.
type aead struct {
	key [32]byte
}

// New returns a cipher.AEAD using this ChaCha20-Poly1305 implementation.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("chacha20poly1305: key must be %d bytes, got %d", KeySize, len(key))
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

func (a *aead) NonceSize() int { return NonceSize }
func (a *aead) Overhead() int  { return TagSize }

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: incorrect nonce length")
	}
	ct, tag := Seal(&a.key, (*[12]byte)(nonce), additionalData, plaintext)
	dst = append(dst, ct...)
	return append(dst, tag[:]...)
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: incorrect nonce length")
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	ct := ciphertext[:len(ciphertext)-TagSize]
	tag := ciphertext[len(ciphertext)-TagSize:]
	pt, err := Open(&a.key, (*[12]byte)(nonce), additionalData, ct, tag)
	if err != nil {
		return nil, err
	}
	return append(dst, pt...), nil
}

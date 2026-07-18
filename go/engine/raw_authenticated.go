package engine

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/alleato-llc/dorado/go/skein"
)

// Domain separators for the raw-key authenticated construction (encrypt-then-MAC
// over a caller-supplied key, no password, no KDF). Distinct from frameDomain so a
// raw-authenticated frame's tag can never collide with or be replayed as a
// password-container frame's tag, even under key reuse across both paths.
const (
	rawAuthEncDomain = "DRDOrawE"
	rawAuthMacDomain = "DRDOrawM"
	rawFrameDomain   = "DRDOrwFr"
)

// splitRawKey splits a caller-supplied raw key into an independent encryption
// subkey and MAC subkey, each derived via domain-separated Skein-512 keyed
// hashing (key is the MAC key, the domain label is the message). This is
// deliberately not a password KDF: key is assumed to already be high-entropy
// (e.g. from an OS keychain or a CSPRNG), so no cost-parameterized stretching is
// needed, only separation into two subkeys that must not be the same bytes used
// for two different primitives.
func splitRawKey(v Variant, key []byte) ([]byte, error) {
	if len(key) != v.KeyLen() {
		return nil, fmt.Errorf("%w: raw key must be %d bytes for this variant, got %d", ErrInvalidParams, v.KeyLen(), len(key))
	}
	keymat := make([]byte, v.KeyLen()+macKeyLen)
	copy(keymat[:v.KeyLen()], skein.MAC(key, v.KeyLen(), []byte(rawAuthEncDomain)))
	copy(keymat[v.KeyLen():], skein.MAC(key, macKeyLen, []byte(rawAuthMacDomain)))
	return keymat, nil
}

// rawFrameAAD builds the authenticated data for a raw-mode frame: a domain
// separator, the tweak and IV (for the first frame only, binding the
// parameters -- raw mode has no header to bind them into the way the password
// container does), the frame index, the last flag, and the ciphertext. Mirrors
// frameAAD, substituting tweak+IV for the header.
func rawFrameAAD(tweak [16]byte, iv []byte, index uint64, isLast bool, ciphertext []byte) []byte {
	aad := make([]byte, 0, len(ciphertext)+64)
	aad = append(aad, rawFrameDomain...)
	if index == 0 {
		aad = append(aad, tweak[:]...)
		aad = append(aad, iv...)
	}
	aad = binary.BigEndian.AppendUint64(aad, index)
	aad = append(aad, boolByte(isLast))
	aad = appendU32(aad, uint32(len(ciphertext)))
	aad = append(aad, ciphertext...)
	return aad
}

// validateRawAuthParams validates the IV and chunk size shared by the
// raw-authenticated encrypt and decrypt paths.
func validateRawAuthParams(v Variant, iv []byte, chunkSize uint32) error {
	if len(iv) != v.BlockLen() {
		return fmt.Errorf("%w: iv must be %d bytes for this variant, got %d", ErrInvalidParams, v.BlockLen(), len(iv))
	}
	if chunkSize == 0 || int(chunkSize)%v.BlockLen() != 0 {
		return fmt.Errorf("%w: chunk size must be a positive multiple of the block size (%d), got %d", ErrInvalidParams, v.BlockLen(), chunkSize)
	}
	return nil
}

// EncryptRawAuthenticatedStream streams authenticated CTR with a
// caller-supplied key: encrypt-then-MAC, no password, no KDF (see
// splitRawKey). Data streams in fixed-size authenticated chunks, reusing the
// same frame construction as the password container (frameAAD-shaped AAD,
// writeFrame/readFrame), so truncation, reordering, and dropped chunks are
// all rejected on decryption exactly as they are there. There is no header:
// the caller must supply the same variant, tweak, iv, mac, and chunkSize on
// decrypt as were used to encrypt, and remember them out of band (nothing
// here is written to the stream itself, matching RawCTRStream's no-header
// philosophy).
func EncryptRawAuthenticatedStream(v Variant, key []byte, tweak [16]byte, iv []byte, mac MacID, chunkSize uint32, r io.Reader, w io.Writer) error {
	if err := validateRawAuthParams(v, iv, chunkSize); err != nil {
		return err
	}
	keymat, err := splitRawKey(v, key)
	if err != nil {
		return err
	}
	defer wipeKeys(keymat) // wipe the derived keys on the way out
	encKey := keymat[:v.KeyLen()]
	macKey := keymat[v.KeyLen():]

	block, err := newBlock(v, encKey, tweak[:])
	if err != nil {
		return err
	}
	defer zeroizeBlock(block)
	stream := cipher.NewCTR(block, iv)

	// Read one chunk ahead so each chunk knows whether it is the last (which
	// is authenticated, defeating truncation) -- same shape as
	// EncryptPasswordStream.
	current := make([]byte, chunkSize)
	nCur, err := readSome(r, current)
	if err != nil {
		return err
	}
	var index uint64
	for {
		next := make([]byte, chunkSize)
		nNext, err := readSome(r, next)
		if err != nil {
			return err
		}
		isLast := nNext == 0

		chunk := make([]byte, nCur)
		stream.XORKeyStream(chunk, current[:nCur])
		tag := macTag(mac, macKey, rawFrameAAD(tweak, iv, index, isLast, chunk))
		if err := writeFrame(w, isLast, chunk, tag); err != nil {
			return err
		}
		if isLast {
			break
		}
		index++
		current = next
		nCur = nNext
	}
	return nil
}

// DecryptRawAuthenticatedStream decrypts an EncryptRawAuthenticatedStream
// stream. Each frame's tag is verified in constant time before that frame is
// decrypted, so a wrong key or a corrupted or tampered stream is reported as
// ErrAuthFailed instead of silently producing garbage or attacker-influenced
// plaintext -- the failure mode RawCTRStream cannot detect.
func DecryptRawAuthenticatedStream(v Variant, key []byte, tweak [16]byte, iv []byte, mac MacID, chunkSize uint32, r io.Reader, w io.Writer) error {
	if err := validateRawAuthParams(v, iv, chunkSize); err != nil {
		return err
	}
	if chunkSize > MaxChunkBytes() {
		return fmt.Errorf("%w: chunk size %d exceeds the accepted maximum", ErrInvalidParams, chunkSize)
	}
	keymat, err := splitRawKey(v, key)
	if err != nil {
		return err
	}
	defer wipeKeys(keymat) // wipe the derived keys on the way out
	encKey := keymat[:v.KeyLen()]
	macKey := keymat[v.KeyLen():]

	block, err := newBlock(v, encKey, tweak[:])
	if err != nil {
		return err
	}
	defer zeroizeBlock(block)
	stream := cipher.NewCTR(block, iv)

	var index uint64
	for {
		fr, err := readFrame(r, chunkSize)
		if err != nil {
			return err
		}
		// Verify before decrypting (which also rejects a wrong key).
		if !macVerify(mac, macKey, rawFrameAAD(tweak, iv, index, fr.isLast, fr.ciphertext), fr.tag) {
			return ErrAuthFailed
		}
		plain := make([]byte, len(fr.ciphertext))
		stream.XORKeyStream(plain, fr.ciphertext)
		if _, err := w.Write(plain); err != nil {
			return err
		}
		if fr.isLast {
			break
		}
		if len(fr.ciphertext) != int(chunkSize) {
			return fmt.Errorf("%w: non-final chunk is not full size", ErrMalformedContainer)
		}
		index++
	}
	return nil
}

// EncryptRawAuthenticatedBytes is an in-memory wrapper over
// EncryptRawAuthenticatedStream.
func EncryptRawAuthenticatedBytes(v Variant, key []byte, tweak [16]byte, iv []byte, mac MacID, chunkSize uint32, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := EncryptRawAuthenticatedStream(v, key, tweak, iv, mac, chunkSize, bytes.NewReader(plaintext), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptRawAuthenticatedBytes is an in-memory wrapper over
// DecryptRawAuthenticatedStream.
func DecryptRawAuthenticatedBytes(v Variant, key []byte, tweak [16]byte, iv []byte, mac MacID, chunkSize uint32, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := DecryptRawAuthenticatedStream(v, key, tweak, iv, mac, chunkSize, bytes.NewReader(data), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

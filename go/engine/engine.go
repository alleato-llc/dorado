package engine

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"

	"github.com/alleato-llc/dorado/go/threefish"
)

// wipeKeys zeroes derived key material and prevents the compiler from eliding the
// clear as a dead store. Go's heap is non-moving, so a heap slice stays put; this
// is a reliable best-effort wipe, not a language-level guarantee.
func wipeKeys(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

const frameDomain = "DRDOchnk"

func newBlock(v Variant, key, tweak []byte) (cipher.Block, error) {
	switch v {
	case T256:
		return threefish.New256(key, tweak)
	case T512:
		return threefish.New512(key, tweak)
	case T1024:
		return threefish.New1024(key, tweak)
	}
	return nil, fmt.Errorf("%w: unknown variant %d", ErrInvalidParams, v)
}

// zeroizeBlock wipes a cipher's expanded key schedule if it supports it (the
// threefish package does), so the key material does not linger until the GC runs.
func zeroizeBlock(block cipher.Block) {
	if z, ok := block.(interface{ Zeroize() }); ok {
		z.Zeroize()
	}
}

// PasswordOptions controls password encryption. Decryption reads them from the
// header.
type PasswordOptions struct {
	Variant   Variant
	KDF       KDFParams
	Mac       MacID
	Tweak     [16]byte
	ChunkSize uint32
	Label     []byte
}

// DefaultOptions returns sensible defaults: Threefish-256, Argon2id, Skein-512
// MAC, 64 KiB chunks, no label.
func DefaultOptions() PasswordOptions {
	return PasswordOptions{
		Variant:   T256,
		KDF:       KDFParams{Kind: Argon2id, MCost: 64 * 1024, TCost: 3, PCost: 1},
		Mac:       MacSkein,
		ChunkSize: defaultChunkBytes,
	}
}

// frameAAD builds the authenticated data for a frame: a domain separator, the
// whole header (chunk 0 only), the index, the last flag, the length, and the
// ciphertext.
func frameAAD(headerBytes []byte, index uint64, isLast bool, ciphertext []byte) []byte {
	aad := make([]byte, 0, len(ciphertext)+len(headerBytes)+32)
	aad = append(aad, frameDomain...)
	if index == 0 {
		aad = append(aad, headerBytes...)
	}
	aad = binary.BigEndian.AppendUint64(aad, index)
	aad = append(aad, boolByte(isLast))
	aad = appendU32(aad, uint32(len(ciphertext)))
	aad = append(aad, ciphertext...)
	return aad
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func writeFrame(w io.Writer, isLast bool, ciphertext, tag []byte) error {
	head := make([]byte, 5)
	head[0] = boolByte(isLast)
	binary.BigEndian.PutUint32(head[1:], uint32(len(ciphertext)))
	if _, err := w.Write(head); err != nil {
		return err
	}
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}
	_, err := w.Write(tag)
	return err
}

type frame struct {
	isLast     bool
	ciphertext []byte
	tag        []byte
}

func readFrame(r io.Reader, chunkSize uint32) (*frame, error) {
	head := make([]byte, 5)
	n, err := io.ReadFull(r, head)
	if n == 0 && err != nil {
		return nil, fmt.Errorf("%w: stream ended before the final chunk (truncated)", ErrMalformedContainer)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: incomplete frame header (truncated)", ErrMalformedContainer)
	}
	if head[0] > 1 {
		return nil, fmt.Errorf("%w: invalid frame flag %d", ErrMalformedContainer, head[0])
	}
	isLast := head[0] == 1
	ctLen := binary.BigEndian.Uint32(head[1:])
	if ctLen > chunkSize {
		return nil, fmt.Errorf("%w: frame length exceeds the header chunk size", ErrMalformedContainer)
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(r, ct); err != nil {
		return nil, fmt.Errorf("%w: truncated frame ciphertext", ErrMalformedContainer)
	}
	tag := make([]byte, tagLen)
	if _, err := io.ReadFull(r, tag); err != nil {
		return nil, fmt.Errorf("%w: truncated frame tag", ErrMalformedContainer)
	}
	return &frame{isLast, ct, tag}, nil
}

// readSome reads up to len(buf) bytes, returning how many; a short count means
// end of input (not an error).
func readSome(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, nil
	}
	return n, err
}

// EncryptPasswordStream encrypts r into w as an authenticated password container.
func EncryptPasswordStream(password []byte, opts PasswordOptions, r io.Reader, w io.Writer) error {
	if len(opts.Label) > maxLabelLen {
		return fmt.Errorf("%w: label too long (%d bytes, max %d)", ErrInvalidParams, len(opts.Label), maxLabelLen)
	}
	v := opts.Variant
	salt := make([]byte, 16)
	iv := make([]byte, v.BlockLen())
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	keymat, err := derive(opts.KDF, password, salt, v.KeyLen()+macKeyLen)
	if err != nil {
		return err
	}
	defer wipeKeys(keymat) // wipe the derived keys on the way out
	encKey := keymat[:v.KeyLen()]
	macKey := keymat[v.KeyLen():]

	h := &Header{
		Version:   formatVersion,
		Variant:   v,
		KDF:       opts.KDF,
		Mac:       opts.Mac,
		ChunkSize: opts.ChunkSize,
		Salt:      salt,
		Tweak:     opts.Tweak,
		IV:        iv,
		Label:     opts.Label,
	}
	headerBytes := h.marshal()

	block, err := newBlock(v, encKey, opts.Tweak[:])
	if err != nil {
		return err
	}
	defer zeroizeBlock(block)
	stream := cipher.NewCTR(block, iv)

	if _, err := w.Write(headerBytes); err != nil {
		return err
	}

	// Read one chunk ahead so each chunk knows whether it is the last.
	current := make([]byte, opts.ChunkSize)
	nCur, err := readSome(r, current)
	if err != nil {
		return err
	}
	var index uint64
	for {
		next := make([]byte, opts.ChunkSize)
		nNext, err := readSome(r, next)
		if err != nil {
			return err
		}
		isLast := nNext == 0

		chunk := make([]byte, nCur)
		stream.XORKeyStream(chunk, current[:nCur])
		tag := macTag(opts.Mac, macKey, frameAAD(headerBytes, index, isLast, chunk))
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

// DecryptPasswordStream decrypts an authenticated password container from r into w.
func DecryptPasswordStream(password []byte, r io.Reader, w io.Writer) error {
	return DecryptPasswordStreamExpecting(password, nil, r, w)
}

// DecryptPasswordStreamExpecting is like DecryptPasswordStream, but if
// expectedLabel is non-nil the container's label must equal it, or decryption
// fails before any plaintext is written.
func DecryptPasswordStreamExpecting(password, expectedLabel []byte, r io.Reader, w io.Writer) error {
	h, err := readHeader(r)
	if err != nil {
		return err
	}
	if expectedLabel != nil && !bytes.Equal(expectedLabel, h.Label) {
		return fmt.Errorf("%w: container label does not match the expected label", ErrInvalidParams)
	}
	headerBytes := h.marshal()
	blockLen := h.Variant.BlockLen()
	if h.ChunkSize == 0 || h.ChunkSize > MaxChunkBytes() || int(h.ChunkSize)%blockLen != 0 {
		return fmt.Errorf("%w: invalid chunk size %d in header", ErrInvalidParams, h.ChunkSize)
	}
	if err := validate(h.KDF); err != nil {
		return err
	}

	keymat, err := derive(h.KDF, password, h.Salt, h.Variant.KeyLen()+macKeyLen)
	if err != nil {
		return err
	}
	defer wipeKeys(keymat) // wipe the derived keys on the way out
	encKey := keymat[:h.Variant.KeyLen()]
	macKey := keymat[h.Variant.KeyLen():]

	block, err := newBlock(h.Variant, encKey, h.Tweak[:])
	if err != nil {
		return err
	}
	defer zeroizeBlock(block)
	stream := cipher.NewCTR(block, h.IV)

	var index uint64
	for {
		fr, err := readFrame(r, h.ChunkSize)
		if err != nil {
			return err
		}
		if !macVerify(h.Mac, macKey, frameAAD(headerBytes, index, fr.isLast, fr.ciphertext), fr.tag) {
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
		if len(fr.ciphertext) != int(h.ChunkSize) {
			return fmt.Errorf("%w: non-final chunk is not full size", ErrMalformedContainer)
		}
		index++
	}
	return nil
}

// RawCTRStream applies bare, unauthenticated CTR with a user-supplied key and IV.
// Encrypt and decrypt are the same operation.
func RawCTRStream(v Variant, key, tweak, iv []byte, r io.Reader, w io.Writer) error {
	if len(iv) != v.BlockLen() {
		return fmt.Errorf("%w: iv must be %d bytes, got %d", ErrInvalidParams, v.BlockLen(), len(iv))
	}
	block, err := newBlock(v, key, tweak)
	if err != nil {
		return err
	}
	defer zeroizeBlock(block)
	stream := cipher.NewCTR(block, iv)
	_, err = io.Copy(w, cipher.StreamReader{S: stream, R: r})
	return err
}

// ContainerInfo is the non-secret description of a password container's header.
type ContainerInfo struct {
	Version   byte
	Variant   Variant
	KDF       KDFParams
	Mac       MacID
	ChunkSize uint32
	SaltLen   int
	Tweak     [16]byte
	Label     []byte
}

// Inspect reads and describes a container's header without decrypting it.
func Inspect(r io.Reader) (*ContainerInfo, error) {
	h, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	return &ContainerInfo{
		Version:   h.Version,
		Variant:   h.Variant,
		KDF:       h.KDF,
		Mac:       h.Mac,
		ChunkSize: h.ChunkSize,
		SaltLen:   len(h.Salt),
		Tweak:     h.Tweak,
		Label:     h.Label,
	}, nil
}

// EncryptPasswordBytes is an in-memory wrapper over EncryptPasswordStream.
func EncryptPasswordBytes(password []byte, opts PasswordOptions, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := EncryptPasswordStream(password, opts, bytes.NewReader(plaintext), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptPasswordBytes is an in-memory wrapper over DecryptPasswordStream.
func DecryptPasswordBytes(password, data []byte) ([]byte, error) {
	return DecryptPasswordBytesExpecting(password, nil, data)
}

// DecryptPasswordBytesExpecting is an in-memory wrapper over
// DecryptPasswordStreamExpecting.
func DecryptPasswordBytesExpecting(password, expectedLabel, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := DecryptPasswordStreamExpecting(password, expectedLabel, bytes.NewReader(data), &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

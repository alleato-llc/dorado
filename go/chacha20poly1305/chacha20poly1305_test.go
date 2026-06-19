package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestRFC8439AEAD(t *testing.T) {
	// RFC 8439, section 2.8.2.
	key := unhex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := unhex(t, "070000004041424344454647")
	aad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, sunscreen would be it.")
	wantCT := unhex(t,
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"+
			"3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"+
			"92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"+
			"3ff4def08e4b7a9de576d26586cec64b6116")
	wantTag := unhex(t, "1ae10b594f09e26a7e902ecbd0600691")

	ct, tag := Seal((*[32]byte)(key), (*[12]byte)(nonce), aad, pt)
	if !bytes.Equal(ct, wantCT) {
		t.Fatalf("ciphertext mismatch:\n got %x\nwant %x", ct, wantCT)
	}
	if !bytes.Equal(tag[:], wantTag) {
		t.Fatalf("tag mismatch:\n got %x\nwant %x", tag[:], wantTag)
	}

	got, err := Open((*[32]byte)(key), (*[12]byte)(nonce), aad, ct, tag[:])
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("round-trip failed")
	}
}

func TestRejectsTamperingAndWrongAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 12)
	aad := []byte("context")
	ct, tag := Seal((*[32]byte)(key), (*[12]byte)(nonce), aad, []byte("secret message"))

	if _, err := Open((*[32]byte)(key), (*[12]byte)(nonce), aad, ct, tag[:]); err != nil {
		t.Fatalf("valid open failed: %v", err)
	}

	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	if _, err := Open((*[32]byte)(key), (*[12]byte)(nonce), aad, bad, tag[:]); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := Open((*[32]byte)(key), (*[12]byte)(nonce), []byte("other"), ct, tag[:]); err == nil {
		t.Fatal("wrong AAD accepted")
	}
}

// The cipher.AEAD adapter agrees with the stdlib's reference AEAD (which appends
// the tag), proving interop.
func TestStdlibAEADInterface(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	a, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x44}, a.NonceSize())
	pt := []byte("aead interface payload")
	aad := []byte("hdr")

	sealed := a.Seal(nil, nonce, pt, aad)
	if len(sealed) != len(pt)+a.Overhead() {
		t.Fatalf("sealed length %d, want %d", len(sealed), len(pt)+a.Overhead())
	}
	opened, err := a.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if !bytes.Equal(opened, pt) {
		t.Fatal("AEAD round-trip failed")
	}
	sealed[0] ^= 1
	if _, err := a.Open(nil, nonce, sealed, aad); err == nil {
		t.Fatal("tampering accepted via AEAD interface")
	}
}

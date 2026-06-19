package chacha

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

func TestRFC8439BlockFunction(t *testing.T) {
	// RFC 8439, section 2.3.2.
	key := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := unhex(t, "000000090000004a00000000")
	want := unhex(t,
		"10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"+
			"d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

	ks := Block((*[32]byte)(key), 1, (*[12]byte)(nonce))
	if !bytes.Equal(ks[:], want) {
		t.Fatalf("keystream mismatch:\n got %x\nwant %x", ks[:], want)
	}
}

func TestRFC8439Encryption(t *testing.T) {
	// RFC 8439, section 2.4.2: the "sunscreen" plaintext.
	key := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	nonce := unhex(t, "000000000000004a00000000")
	pt := []byte("Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, sunscreen would be it.")
	want := unhex(t,
		"6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"+
			"f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"+
			"07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"+
			"5af90bbf74a35be6b40b8eedf2785e42874d")

	buf := append([]byte(nil), pt...)
	Apply((*[32]byte)(key), 1, (*[12]byte)(nonce), buf)
	if !bytes.Equal(buf, want) {
		t.Fatalf("encryption mismatch:\n got %x\nwant %x", buf, want)
	}
	Apply((*[32]byte)(key), 1, (*[12]byte)(nonce), buf)
	if !bytes.Equal(buf, pt) {
		t.Fatal("ChaCha20 did not round-trip")
	}
}

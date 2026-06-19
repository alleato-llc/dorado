package poly1305

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

func TestRFC8439Tag(t *testing.T) {
	// RFC 8439, section 2.5.2.
	key := unhex(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	msg := []byte("Cryptographic Forum Research Group")
	want := unhex(t, "a8061dc1305136c6c22b8baf0c0127a9")

	tag := MAC((*[32]byte)(key), msg)
	if !bytes.Equal(tag[:], want) {
		t.Fatalf("tag mismatch:\n got %x\nwant %x", tag[:], want)
	}
}

func TestIncrementalMatchesOneShot(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0x24
	}
	msg := make([]byte, 200)
	for i := range msg {
		msg[i] = byte(i)
	}
	want := MAC(&key, msg)

	for _, step := range []int{1, 3, 7, 16, 31, 64} {
		p := New(&key)
		for i := 0; i < len(msg); i += step {
			p.Update(msg[i:min(i+step, len(msg))])
		}
		if got := p.Finalize(); got != want {
			t.Fatalf("mismatch at step %d", step)
		}
	}
}

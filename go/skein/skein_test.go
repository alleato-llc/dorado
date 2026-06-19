package skein

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestKnownAnswerVectors(t *testing.T) {
	// Official Skein-512-512 digest of the empty message.
	empty512 := "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4" +
		"1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a"
	if got := hex.EncodeToString(Hash(64, nil)); got != empty512 {
		t.Fatalf("empty 512 mismatch:\n got %s\nwant %s", got, empty512)
	}

	// Skein-512-256 of "abc" (cross-checked against the differentially verified
	// dorado Rust implementation).
	abc256 := "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527"
	if got := hex.EncodeToString(Hash(32, []byte("abc"))); got != abc256 {
		t.Fatalf("abc 256 mismatch:\n got %s\nwant %s", got, abc256)
	}
}

func TestIncrementalMatchesOneShot(t *testing.T) {
	msg := make([]byte, 500)
	for i := range msg {
		msg[i] = byte(i)
	}
	want := Hash(32, msg)

	for _, step := range []int{1, 7, 63, 64, 65, 200} {
		h := New(32)
		for i := 0; i < len(msg); i += step {
			h.Write(msg[i:min(i+step, len(msg))])
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			t.Fatalf("mismatch at step %d", step)
		}
	}

	// Sum must not consume state: a second Sum gives the same digest, and we can
	// keep writing.
	h := New(32)
	h.Write(msg[:100])
	_ = h.Sum(nil)
	if !bytes.Equal(h.Sum(nil), Hash(32, msg[:100])) {
		t.Fatal("Sum changed the hasher state")
	}
}

func TestMACIsKeyAndMessageSensitive(t *testing.T) {
	key := bytes.Repeat([]byte{0x9c}, 32)
	a := MAC(key, 32, []byte("authenticate me"))
	if len(a) != 32 {
		t.Fatalf("tag length %d", len(a))
	}
	if bytes.Equal(a, MAC(bytes.Repeat([]byte{0x22}, 32), 32, []byte("authenticate me"))) {
		t.Fatal("different key gave same tag")
	}
	if bytes.Equal(a, MAC(key, 32, []byte("authenticate ne"))) {
		t.Fatal("different message gave same tag")
	}
}

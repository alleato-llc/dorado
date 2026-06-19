package blake3

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"

	ref "lukechampine.com/blake3"
)

func TestOfficialEmptyVector(t *testing.T) {
	// Official BLAKE3 hash of the empty input.
	want := "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
	got := Sum256(nil)
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("empty hash mismatch:\n got %x\nwant %s", got, want)
	}
}

// Differential test against lukechampine.com/blake3 over many sizes spanning
// chunk and tree boundaries, for the 32-byte hash, an extended XOF length, and
// the keyed MAC. This is the Go analogue of the Rust crate's differential test.
func TestDifferentialAgainstReference(t *testing.T) {
	lengths := []int{0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 2049, 4096, 8192, 16384, 32769, 50000}
	r := rand.New(rand.NewSource(1))
	var key [32]byte
	r.Read(key[:])

	for _, n := range lengths {
		msg := make([]byte, n)
		r.Read(msg)

		// 32-byte hash.
		if got, want := Sum256(msg), ref.Sum256(msg); got != want {
			t.Fatalf("hash mismatch at len %d", n)
		}

		// Extended output (XOF), 131 bytes.
		gotX := make([]byte, 131)
		Hash(gotX, msg)
		rh := ref.New(131, nil)
		rh.Write(msg)
		if wantX := rh.Sum(nil); !bytes.Equal(gotX, wantX) {
			t.Fatalf("xof mismatch at len %d", n)
		}

		// Keyed MAC, 32 bytes.
		gotK := make([]byte, 32)
		KeyedMAC(&key, gotK, msg)
		rk := ref.New(32, key[:])
		rk.Write(msg)
		if wantK := rk.Sum(nil); !bytes.Equal(gotK, wantK) {
			t.Fatalf("keyed mismatch at len %d", n)
		}
	}
}

func TestIncrementalMatchesOneShotAndSumIsIdempotent(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	msg := make([]byte, 20000)
	r.Read(msg)
	want := Sum256(msg)

	for _, step := range []int{1, 63, 64, 100, 1023, 1024, 1025, 4096} {
		h := New()
		for i := 0; i < len(msg); i += step {
			h.Write(msg[i:min(i+step, len(msg))])
		}
		if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
			t.Fatalf("mismatch at step %d", step)
		}
	}

	// Sum must not consume state.
	h := New()
	h.Write(msg[:5000])
	first := h.Sum(nil)
	second := h.Sum(nil)
	if !bytes.Equal(first, second) {
		t.Fatal("Sum changed the hasher state")
	}
}

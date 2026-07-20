package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Cross-compatibility: decrypt .mahi fixtures produced by the Rust reference (the
// baseline), one per KDF/MAC/variant plus a labeled and a multi-frame file.
// Checked-in regression guards that the Go port stays byte-compatible with the
// shared format. The reverse direction is verified during development.

var crossPW = []byte("pw-cross")

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("missing fixture %s: %v", name, err)
	}
	return data
}

func TestDecryptsRustFixtures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		expected string
	}{
		{"argon_skein_256.mahi", "rust argon+skein+256"},
		{"scrypt_hmac_512.mahi", "rust scrypt+hmac+512"},
		{"pbkdf2_blake3_1024.mahi", "rust pbkdf2+blake3+1024"},
	} {
		back, err := DecryptPasswordBytes(crossPW, fixture(t, tc.name))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !bytes.Equal(back, []byte(tc.expected)) {
			t.Fatalf("%s: got %q, want %q", tc.name, back, tc.expected)
		}
	}
}

func TestLabeledRustFixture(t *testing.T) {
	data := fixture(t, "labeled.mahi")
	info, err := Inspect(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info.Label, []byte("demo-context")) {
		t.Fatalf("label %q, want %q", info.Label, "demo-context")
	}
	back, err := DecryptPasswordBytesExpecting(crossPW, []byte("demo-context"), data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, []byte("rust labeled payload")) {
		t.Fatalf("got %q", back)
	}
	if _, err := DecryptPasswordBytesExpecting(crossPW, []byte("wrong"), data); err == nil {
		t.Fatal("mismatched label accepted")
	}
}

func TestMultiFrameRustFixture(t *testing.T) {
	back, err := DecryptPasswordBytes(crossPW, fixture(t, "multichunk.mahi"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, bytes.Repeat([]byte("x"), 5000)) {
		t.Fatalf("multichunk plaintext mismatch (len %d)", len(back))
	}
}

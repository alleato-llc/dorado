package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI tests drive cmdCrypt in-process with real files, exercising the
// raw-key paths end to end (flag parsing through the engine). Password mode
// needs a terminal or stdin, so its coverage lives in the engine tests.

const (
	testKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"
	testIVHex  = "0202020202020202020202020202020202020202020202020202020202020202"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readBack(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestRawKeyAuthenticatedByDefault round-trips raw-key mode with no extra
// flags: the output must be the authenticated (encrypt-then-MAC) form, larger
// than the input by the per-chunk framing and tag.
func TestRawKeyAuthenticatedByDefault(t *testing.T) {
	plaintext := []byte("raw-key mode is authenticated unless you opt out")
	in := writeTemp(t, "plain", plaintext)
	ct := filepath.Join(t.TempDir(), "ct")
	back := filepath.Join(t.TempDir(), "back")

	if err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--in", in, "--out", ct}, true); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got := readBack(t, ct); len(got) <= len(plaintext) {
		t.Fatalf("authenticated output must carry framing and a tag: %d <= %d", len(got), len(plaintext))
	}
	if err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--in", ct, "--out", back}, false); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(readBack(t, back), plaintext) {
		t.Fatal("round trip mismatch")
	}
}

// TestRawKeyUnauthenticatedRoundTrip opts out with --unauthenticated: bare
// CTR, output length exactly equal to input length, symmetric in both
// directions.
func TestRawKeyUnauthenticatedRoundTrip(t *testing.T) {
	plaintext := []byte("bare CTR keeps the exact input length")
	in := writeTemp(t, "plain", plaintext)
	ct := filepath.Join(t.TempDir(), "ct")
	back := filepath.Join(t.TempDir(), "back")

	if err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--unauthenticated", "--in", in, "--out", ct}, true); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got := readBack(t, ct)
	if len(got) != len(plaintext) {
		t.Fatalf("bare CTR output length must equal input length: %d != %d", len(got), len(plaintext))
	}
	if bytes.Equal(got, plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	if err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--unauthenticated", "--in", ct, "--out", back}, false); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(readBack(t, back), plaintext) {
		t.Fatal("round trip mismatch")
	}
}

// TestRawKeyTamperRejected flips one ciphertext byte of an authenticated
// raw-key file; decryption must fail instead of silently producing garbage.
func TestRawKeyTamperRejected(t *testing.T) {
	in := writeTemp(t, "plain", []byte("tampering must be detected"))
	ct := filepath.Join(t.TempDir(), "ct")

	if err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--in", in, "--out", ct}, true); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	data := readBack(t, ct)
	data[len(data)/2] ^= 1
	tampered := writeTemp(t, "tampered", data)

	err := cmdCrypt([]string{"--key", testKeyHex, "--iv", testIVHex, "--in", tampered, "--out", filepath.Join(t.TempDir(), "back")}, false)
	if err == nil {
		t.Fatal("decrypting a tampered file must fail")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want an authentication failure, got %v", err)
	}
}

// TestUnauthenticatedRejectedInPasswordMode mirrors the Rust CLI: password
// mode is always authenticated, so --unauthenticated there is an error.
func TestUnauthenticatedRejectedInPasswordMode(t *testing.T) {
	in := writeTemp(t, "plain", []byte("x"))
	err := cmdCrypt([]string{"--password", "--unauthenticated", "--in", in, "--out", filepath.Join(t.TempDir(), "ct")}, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "--unauthenticated is not used in password mode, which is always authenticated"
	if err.Error() != want {
		t.Fatalf("got %q, want %q", err.Error(), want)
	}
}

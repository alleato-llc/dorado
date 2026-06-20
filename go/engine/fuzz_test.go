package engine

import "testing"

// FuzzDecryptPasswordBytes feeds arbitrary bytes to the password-container
// decryptor. It parses an untrusted header and a sequence of authenticated frames,
// so it must never panic, hang, or over-allocate on malformed input; it may only
// return an error (or, vanishingly unlikely, succeed). This is the Go analog of the
// Rust fuzz target; the chunk-size and KDF-cost bounds are what keep it safe.
//
// The seed corpus runs as part of `go test`; for a real campaign:
//
//	go test -run=x -fuzz=FuzzDecryptPasswordBytes ./engine
func FuzzDecryptPasswordBytes(f *testing.F) {
	if ct, err := EncryptPasswordBytes([]byte("fuzz-password"), fastOpts(), []byte("seed plaintext")); err == nil {
		f.Add(ct)
	}
	f.Add([]byte("DRDO"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecryptPasswordBytes([]byte("fuzz-password"), data)
	})
}

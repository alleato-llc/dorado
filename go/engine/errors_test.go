package engine

import (
	"errors"
	"testing"
)

func TestChunkCapFrom(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", defaultMaxChunkBytes},            // unset -> default
		{"garbage", defaultMaxChunkBytes},     // unparseable -> default
		{"65536", 65536},                      // plain value
		{"  1048576  ", 1048576},              // whitespace trimmed
		{"0", 1},                              // clamped up into (0, ...]
		{"4294967295", maxChunkBytes},         // clamped down to the hard ceiling
		{"99999999999", defaultMaxChunkBytes}, // overflows uint32 -> default
	}
	for _, c := range cases {
		if got := chunkCapFrom(c.in); got != c.want {
			t.Errorf("chunkCapFrom(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestErrorsAreClassifiable(t *testing.T) {
	// A non-container is a matchable malformed-container error.
	if _, err := DecryptPasswordBytes([]byte("pw"), []byte("not a dorado file")); !errors.Is(err, ErrMalformedContainer) {
		t.Fatalf("want ErrMalformedContainer, got %v", err)
	}
}

func TestAuthFailureMergedAndMatchable(t *testing.T) {
	ct, err := EncryptPasswordBytes([]byte("pw"), fastOpts(), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, wrong := DecryptPasswordBytes([]byte("nope"), ct)
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 1
	_, tamper := DecryptPasswordBytes([]byte("pw"), tampered)

	if !errors.Is(wrong, ErrAuthFailed) || !errors.Is(tamper, ErrAuthFailed) {
		t.Fatalf("both must be ErrAuthFailed: wrong=%v tamper=%v", wrong, tamper)
	}
	// Identical messages, so neither leaks which case occurred.
	if wrong.Error() != tamper.Error() {
		t.Fatalf("messages must match to avoid an oracle: %q vs %q", wrong, tamper)
	}
}

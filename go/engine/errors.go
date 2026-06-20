package engine

import "errors"

// Sentinel errors for the engine, so callers can classify a failure with
// errors.Is instead of matching strings. Functions wrap these with %w and add
// detail; the wrapped error still satisfies errors.Is for the sentinel.
//
// One deliberate non-distinction: a wrong password and a corrupted or tampered
// file both surface as ErrAuthFailed with the same message. Telling them apart
// would leak whether the key was right, so they are merged on purpose.
var (
	// ErrAuthFailed means authentication failed: a wrong password, or a corrupted
	// or tampered file. These cases are intentionally indistinguishable.
	ErrAuthFailed = errors.New("authentication failed: wrong password or corrupted file")
	// ErrMalformedContainer means the header or a frame is malformed or truncated.
	ErrMalformedContainer = errors.New("malformed container")
	// ErrUnsupportedVersion means the container's format version is not one this
	// build can read.
	ErrUnsupportedVersion = errors.New("unsupported container version")
	// ErrInvalidParams means a parameter was invalid or out of bounds: a key or
	// tweak length, a chunk size, a KDF cost, or a label length.
	ErrInvalidParams = errors.New("invalid parameters")
)

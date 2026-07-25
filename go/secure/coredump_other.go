//go:build !unix

package secure

// SuppressCoreDumps is a no-op on non-Unix platforms, which have no RLIMIT_CORE.
// (The core-dump limit is set in coredump_unix.go.)
func SuppressCoreDumps() {}

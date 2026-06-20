// Package secure provides a best-effort locked, off-heap buffer for the secrets a
// CLI holds (the password), plus a wipe that the compiler will not elide.
//
// Honest limits: Go cannot guarantee a wipe the way Rust's zeroize or C's
// OPENSSL_cleanse can. This package reduces exposure (the buffer is off the Go heap,
// so growable goroutine stacks cannot leave a stale copy behind, and it is mlock'd
// out of swap), and Wipe uses runtime.KeepAlive to defeat dead-store elimination,
// but none of that is a language-level guarantee. A password that first arrives as
// a Go string is still un-wipeable.
package secure

import "runtime"

// Wipe zeroes b and prevents the compiler from removing the clear as a dead store.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

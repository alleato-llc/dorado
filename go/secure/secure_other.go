//go:build !unix

package secure

// Buffer is a heap fallback on non-Unix platforms: wiped on Free, but not mlock'd
// and not off-heap. (The mmap/mlock path is in secure_unix.go.)
type Buffer struct{ mem []byte }

// Alloc returns a heap-backed Buffer of n bytes.
func Alloc(n int) (*Buffer, error) { return &Buffer{mem: make([]byte, n)}, nil }

// Bytes returns the usable slice.
func (b *Buffer) Bytes() []byte { return b.mem }

// Free wipes the buffer.
func (b *Buffer) Free() { Wipe(b.mem) }

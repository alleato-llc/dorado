//go:build unix

package secure

import "golang.org/x/sys/unix"

// Buffer is a page-aligned, off-heap secret buffer (Unix): anonymous mmap memory,
// mlock'd to keep it out of swap, and wiped + unlocked + unmapped on Free. Being
// off the Go heap, it is not subject to garbage-collector stack copies.
type Buffer struct {
	mem []byte // the full mmap'd region (a whole number of pages)
	n   int    // the requested length
}

// Alloc returns a Buffer of at least n usable bytes. mlock is best-effort: a
// failure (for example RLIMIT_MEMLOCK on a locked-down host) is not fatal, the
// buffer is still off-heap and wiped on Free.
func Alloc(n int) (*Buffer, error) {
	pageSize := unix.Getpagesize()
	size := ((n + pageSize - 1) / pageSize) * pageSize
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	_ = unix.Mlock(mem) // best-effort
	return &Buffer{mem: mem, n: n}, nil
}

// Bytes returns the usable slice (length n).
func (b *Buffer) Bytes() []byte { return b.mem[:b.n] }

// Free wipes, unlocks, and unmaps the buffer. The buffer must not be used after.
func (b *Buffer) Free() {
	if b.mem == nil {
		return
	}
	Wipe(b.mem)
	_ = unix.Munlock(b.mem)
	_ = unix.Munmap(b.mem)
	b.mem = nil
}

//go:build unix

package secure

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestSuppressCoreDumpsUnix checks that SuppressCoreDumps actually lowers this
// process's RLIMIT_CORE soft limit to 0. Lowering the test process's own core
// limit is harmless.
func TestSuppressCoreDumpsUnix(t *testing.T) {
	SuppressCoreDumps()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	if lim.Cur != 0 {
		t.Fatalf("RLIMIT_CORE soft limit = %d, want 0", lim.Cur)
	}
}

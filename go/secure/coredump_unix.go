//go:build unix

package secure

import "golang.org/x/sys/unix"

// SuppressCoreDumps sets RLIMIT_CORE (soft and hard) to 0 so a crash cannot write
// a core file to disk. This matters because mlock keeps secret pages out of swap
// but not out of a core dump: a core captures locked pages like any other, so a
// crash could still spill the password or derived keys to disk. Setting the core
// limit to 0 closes that path (libsodium's secure allocator uses MADV_DONTDUMP for
// the same reason).
//
// This is best-effort and honest about its limits: it raises the bar against a
// crash leaving a core file behind, but it is not a defense against root or a live
// debugger. Call it at the very start of main, before any secret can exist. A
// setrlimit failure is swallowed so this never fails the program.
func SuppressCoreDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// Package threefish is a from-scratch implementation of the Threefish tweakable
// block cipher (256/512/1024-bit), the cipher at the core of the Skein hash
// function. It follows the Skein 1.3 specification, including the round-3 NIST
// tweak to the key-schedule constant C240.
//
// This is the Go port of the dorado Rust crate. It is educational and
// unaudited; for real data prefer a vetted library.
//
// Each variant implements the standard library crypto/cipher.Block interface
// (with the tweak fixed at construction), so it composes with cipher.NewCTR and
// the rest of the stdlib. Keys, tweaks, and blocks are little-endian.
package threefish

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// c240 is the Skein 1.3 key-schedule constant (the round-3 NIST value). It keeps
// the extended key word from ever being all-zero.
const c240 uint64 = 0x1BD11BDAA9FC1A22

// Per-variant rotation and permutation tables (Skein 1.3, Table 4 plus the word
// permutations). rot[lane][round%8] is the rotation for that round and MIX lane;
// perm[i] selects which MIX-output word becomes output word i. These are
// verified against official test vectors and must not be changed.
var (
	rot256  = [2][8]uint32{{14, 52, 23, 5, 25, 46, 58, 32}, {16, 57, 40, 37, 33, 12, 22, 32}}
	perm256 = [4]int{0, 3, 2, 1}

	rot512 = [4][8]uint32{
		{46, 33, 17, 44, 39, 13, 25, 8},
		{36, 27, 49, 9, 30, 50, 29, 35},
		{19, 14, 36, 54, 34, 10, 39, 56},
		{37, 42, 39, 56, 24, 17, 43, 22},
	}
	perm512 = [8]int{2, 1, 4, 7, 6, 5, 0, 3}

	rot1024 = [8][8]uint32{
		{24, 38, 33, 5, 41, 16, 31, 9},
		{13, 19, 4, 20, 9, 34, 44, 48},
		{8, 10, 51, 48, 37, 56, 47, 35},
		{47, 55, 13, 41, 31, 51, 46, 52},
		{8, 49, 34, 47, 12, 4, 19, 23},
		{17, 18, 41, 28, 47, 53, 42, 31},
		{22, 23, 59, 16, 44, 42, 44, 37},
		{37, 52, 17, 25, 30, 41, 25, 20},
	}
	perm1024 = [16]int{0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1}
)

// threefish holds one variant's expanded key schedule and per-variant constants.
type threefish struct {
	ek         []uint64 // extended key: nw key words + parity word
	et         [3]uint64
	rot        [][8]uint32
	perm       []int
	rounds     int
	nw         int
	blockBytes int
}

// New256 returns a Threefish-256 block cipher (32-byte key and block, 16-byte
// tweak). The tweak is fixed for the life of the cipher.
func New256(key, tweak []byte) (cipher.Block, error) {
	return newCipher(key, tweak, 4, 72, rot256[:], perm256[:])
}

// New512 returns a Threefish-512 block cipher (64-byte key and block).
func New512(key, tweak []byte) (cipher.Block, error) {
	return newCipher(key, tweak, 8, 72, rot512[:], perm512[:])
}

// New1024 returns a Threefish-1024 block cipher (128-byte key and block).
func New1024(key, tweak []byte) (cipher.Block, error) {
	return newCipher(key, tweak, 16, 80, rot1024[:], perm1024[:])
}

func newCipher(key, tweak []byte, nw, rounds int, rot [][8]uint32, perm []int) (*threefish, error) {
	blockBytes := nw * 8
	if len(key) != blockBytes {
		return nil, fmt.Errorf("threefish: key must be %d bytes, got %d", blockBytes, len(key))
	}
	if len(tweak) != 16 {
		return nil, fmt.Errorf("threefish: tweak must be 16 bytes, got %d", len(tweak))
	}
	// Extended key: the key words plus C240 xored with all of them.
	ek := make([]uint64, nw+1)
	parity := c240
	for i := 0; i < nw; i++ {
		w := binary.LittleEndian.Uint64(key[i*8:])
		ek[i] = w
		parity ^= w
	}
	ek[nw] = parity
	// Extended tweak: t0, t1, t0^t1.
	t0 := binary.LittleEndian.Uint64(tweak[0:])
	t1 := binary.LittleEndian.Uint64(tweak[8:])
	return &threefish{
		ek:         ek,
		et:         [3]uint64{t0, t1, t0 ^ t1},
		rot:        rot,
		perm:       perm,
		rounds:     rounds,
		nw:         nw,
		blockBytes: blockBytes,
	}, nil
}

// BlockSize reports the variant's block size in bytes.
func (c *threefish) BlockSize() int { return c.blockBytes }

// addSubkey injects subkey s into the state word-wise (mod 2^64). uint64
// arithmetic wraps in Go, so no explicit wrapping helper is needed.
func (c *threefish) addSubkey(state []uint64, s int) {
	nw := c.nw
	for i := 0; i < nw; i++ {
		k := c.ek[(s+i)%(nw+1)]
		switch i {
		case nw - 3:
			k += c.et[s%3]
		case nw - 2:
			k += c.et[(s+1)%3]
		case nw - 1:
			k += uint64(s)
		}
		state[i] += k
	}
}

// subSubkey is the inverse of addSubkey.
func (c *threefish) subSubkey(state []uint64, s int) {
	nw := c.nw
	for i := 0; i < nw; i++ {
		k := c.ek[(s+i)%(nw+1)]
		switch i {
		case nw - 3:
			k += c.et[s%3]
		case nw - 2:
			k += c.et[(s+1)%3]
		case nw - 1:
			k += uint64(s)
		}
		state[i] -= k
	}
}

func (c *threefish) encryptState(state []uint64) {
	nw := c.nw
	var scratchArr [16]uint64
	scratch := scratchArr[:nw]
	for r := 0; r < c.rounds; r++ {
		if r%4 == 0 {
			c.addSubkey(state, r/4)
		}
		for j := 0; j < nw/2; j++ {
			x0 := state[2*j]
			x1 := state[2*j+1]
			y0 := x0 + x1
			y1 := bits.RotateLeft64(x1, int(c.rot[j][r%8])) ^ y0
			state[2*j] = y0
			state[2*j+1] = y1
		}
		for i := 0; i < nw; i++ {
			scratch[i] = state[c.perm[i]]
		}
		copy(state, scratch)
	}
	c.addSubkey(state, c.rounds/4)
}

func (c *threefish) decryptState(state []uint64) {
	nw := c.nw
	var scratchArr [16]uint64
	scratch := scratchArr[:nw]
	c.subSubkey(state, c.rounds/4)
	for r := c.rounds - 1; r >= 0; r-- {
		for i := 0; i < nw; i++ {
			scratch[c.perm[i]] = state[i]
		}
		copy(state, scratch)
		for j := 0; j < nw/2; j++ {
			y0 := state[2*j]
			y1 := state[2*j+1]
			x1 := bits.RotateLeft64(y1^y0, -int(c.rot[j][r%8]))
			x0 := y0 - x1
			state[2*j] = x0
			state[2*j+1] = x1
		}
		if r%4 == 0 {
			c.subSubkey(state, r/4)
		}
	}
}

// Encrypt encrypts one block from src into dst (which may overlap).
func (c *threefish) Encrypt(dst, src []byte) {
	c.crypt(dst, src, true)
}

// Decrypt decrypts one block from src into dst (which may overlap).
func (c *threefish) Decrypt(dst, src []byte) {
	c.crypt(dst, src, false)
}

func (c *threefish) crypt(dst, src []byte, encrypt bool) {
	if len(src) < c.blockBytes {
		panic("threefish: input not full block")
	}
	if len(dst) < c.blockBytes {
		panic("threefish: output not full block")
	}
	state := make([]uint64, c.nw)
	for i := 0; i < c.nw; i++ {
		state[i] = binary.LittleEndian.Uint64(src[i*8:])
	}
	if encrypt {
		c.encryptState(state)
	} else {
		c.decryptState(state)
	}
	for i := 0; i < c.nw; i++ {
		binary.LittleEndian.PutUint64(dst[i*8:], state[i])
	}
}

// Package skein is a from-scratch Skein-512 hash and MAC (Skein 1.3), built on
// Threefish-512 via UBI (Unique Block Iteration). This is the hash function
// Threefish was designed to power.
//
// Skein512 is incremental and implements the standard library hash.Hash
// interface. The output length is fixed at construction (Skein folds it into the
// configuration block). This is the Go port of the dorado Rust crate's skein
// module.
package skein

import (
	"encoding/binary"
	"hash"

	"github.com/alleato-llc/dorado/go/threefish"
)

const blockLen = 64 // Skein-512 block size in bytes.

// UBI block type values (the 6-bit type field of the tweak).
const (
	tKey uint64 = 0
	tCfg uint64 = 4
	tMsg uint64 = 48
	tOut uint64 = 63
)

// tweak builds the 128-bit UBI tweak (16 little-endian bytes) for a block at
// byte position of a UBI pass of type ty, with the first/final flags.
func tweak(position, ty uint64, first, last bool) []byte {
	t1 := ty << 56
	if first {
		t1 |= 1 << 62
	}
	if last {
		t1 |= 1 << 63
	}
	tw := make([]byte, 16)
	binary.LittleEndian.PutUint64(tw[0:], position)
	binary.LittleEndian.PutUint64(tw[8:], t1)
	return tw
}

// ubi runs one full UBI pass, chaining msg into the chaining value g. An empty
// message processes a single zero block at position 0. Used for the (bounded)
// configuration and key passes.
func ubi(g *[64]byte, msg []byte, ty uint64) {
	total := len(msg)
	offset := 0
	var position uint64
	first := true
	for {
		take := min(total-offset, blockLen)
		var block [64]byte
		copy(block[:], msg[offset:offset+take])
		position += uint64(take)
		offset += take
		last := offset >= total

		c, _ := threefish.New512(g[:], tweak(position, ty, first, last))
		var enc [64]byte
		c.Encrypt(enc[:], block[:])
		for i := range 64 {
			g[i] = enc[i] ^ block[i]
		}
		first = false
		if last {
			break
		}
	}
}

// configBlock is the 32-byte Skein configuration block for an output of outBits.
func configBlock(outBits uint64) [32]byte {
	var c [32]byte
	copy(c[0:4], "SHA3") // schema identifier
	c[4] = 1             // version 1 (16-bit little-endian)
	binary.LittleEndian.PutUint64(c[8:16], outBits)
	return c
}

// outputInto fills out from the final chaining value via the output UBI over an
// incrementing counter.
func outputInto(g *[64]byte, out []byte) {
	var counter uint64
	written := 0
	for written < len(out) {
		block := *g
		var ctr [8]byte
		binary.LittleEndian.PutUint64(ctr[:], counter)
		ubi(&block, ctr[:], tOut)
		n := min(blockLen, len(out)-written)
		copy(out[written:written+n], block[:n])
		written += n
		counter++
	}
}

// Skein512 is an incremental Skein-512 hash or MAC. It implements hash.Hash.
type Skein512 struct {
	g         [64]byte
	initG     [64]byte // chaining value after config/key, for Reset
	outLen    int
	buffer    [64]byte
	bufferLen int
	position  uint64
	first     bool
}

// New starts an unkeyed hash producing outLen bytes.
func New(outLen int) *Skein512 {
	var g [64]byte
	cfg := configBlock(uint64(outLen) * 8)
	ubi(&g, cfg[:], tCfg)
	return &Skein512{g: g, initG: g, outLen: outLen, first: true}
}

// NewMAC starts a keyed MAC producing outLen bytes, absorbing key first.
func NewMAC(key []byte, outLen int) *Skein512 {
	var g [64]byte
	if len(key) > 0 {
		ubi(&g, key, tKey)
	}
	cfg := configBlock(uint64(outLen) * 8)
	ubi(&g, cfg[:], tCfg)
	return &Skein512{g: g, initG: g, outLen: outLen, first: true}
}

func (s *Skein512) commitBlock(block *[64]byte, nbytes int, last bool) {
	s.position += uint64(nbytes)
	c, _ := threefish.New512(s.g[:], tweak(s.position, tMsg, s.first, last))
	var enc [64]byte
	c.Encrypt(enc[:], block[:])
	for i := range 64 {
		s.g[i] = enc[i] ^ block[i]
	}
	s.first = false
}

// Write feeds message bytes. The final block is held back for Sum, since only
// finalization knows which block is last. Never returns an error.
func (s *Skein512) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	if s.bufferLen > 0 {
		take := min(blockLen-s.bufferLen, len(p))
		copy(s.buffer[s.bufferLen:], p[:take])
		s.bufferLen += take
		p = p[take:]
		if s.bufferLen == blockLen && len(p) > 0 {
			full := s.buffer
			s.commitBlock(&full, blockLen, false)
			s.bufferLen = 0
		}
	}
	for len(p) > blockLen {
		var block [64]byte
		copy(block[:], p[:blockLen])
		s.commitBlock(&block, blockLen, false)
		p = p[blockLen:]
	}
	if len(p) > 0 {
		copy(s.buffer[:], p)
		s.bufferLen = len(p)
	}
	return n, nil
}

// Sum appends the digest to b without changing the hasher state (it finalizes a
// copy), so writing may continue afterward.
func (s *Skein512) Sum(b []byte) []byte {
	dup := *s
	var block [64]byte
	copy(block[:], dup.buffer[:dup.bufferLen])
	dup.commitBlock(&block, dup.bufferLen, true)
	out := make([]byte, dup.outLen)
	outputInto(&dup.g, out)
	return append(b, out...)
}

// Reset returns the hasher to its just-constructed state (after config/key).
func (s *Skein512) Reset() {
	s.g = s.initG
	s.buffer = [64]byte{}
	s.bufferLen = 0
	s.position = 0
	s.first = true
}

// Size is the output length in bytes.
func (s *Skein512) Size() int { return s.outLen }

// BlockSize is the UBI block size (64 bytes).
func (s *Skein512) BlockSize() int { return blockLen }

var _ hash.Hash = (*Skein512)(nil)

// Hash is the one-shot Skein-512 hash of msg with outLen output bytes.
func Hash(outLen int, msg []byte) []byte {
	h := New(outLen)
	h.Write(msg)
	return h.Sum(nil)
}

// MAC is the one-shot Skein-512 keyed MAC producing outLen bytes.
func MAC(key []byte, outLen int, msg []byte) []byte {
	h := NewMAC(key, outLen)
	h.Write(msg)
	return h.Sum(nil)
}

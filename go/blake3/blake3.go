// Package blake3 is a from-scratch BLAKE3 hash and keyed MAC. It uses the
// streaming chunk-stack algorithm: input is split into 1024-byte chunks, each
// compressed to a chaining value, and chaining values are merged pairwise into a
// Merkle tree up to a single root, all while holding only fixed-size state.
//
// Hasher implements the standard library hash.Hash interface (32-byte output);
// the inherent finalize is an extendable-output function for any length. This is
// the Go port of the dorado Rust crate's blake3 module.
package blake3

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	blockBytes = 64
	chunkBytes = 1024

	chunkStart = 1 << 0
	chunkEnd   = 1 << 1
	flagParent = 1 << 2
	flagRoot   = 1 << 3
	keyedHash  = 1 << 4
)

var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var msgPermutation = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func g(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + my
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

// compress is the BLAKE3 compression function, returning all 16 output words.
func compress(cv *[8]uint32, block *[16]uint32, counter uint64, bLen, flags uint32) [16]uint32 {
	state := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter), uint32(counter >> 32), bLen, flags,
	}
	m := *block
	for round := 0; round < 7; round++ {
		g(&state, 0, 4, 8, 12, m[0], m[1])
		g(&state, 1, 5, 9, 13, m[2], m[3])
		g(&state, 2, 6, 10, 14, m[4], m[5])
		g(&state, 3, 7, 11, 15, m[6], m[7])
		g(&state, 0, 5, 10, 15, m[8], m[9])
		g(&state, 1, 6, 11, 12, m[10], m[11])
		g(&state, 2, 7, 8, 13, m[12], m[13])
		g(&state, 3, 4, 9, 14, m[14], m[15])
		if round < 6 {
			var permuted [16]uint32
			for i := range 16 {
				permuted[i] = m[msgPermutation[i]]
			}
			m = permuted
		}
	}
	for i := range 8 {
		state[i] ^= state[i+8]
		state[i+8] ^= cv[i]
	}
	return state
}

func wordsFromBlock(b []byte) [16]uint32 {
	var padded [blockBytes]byte
	copy(padded[:], b)
	var words [16]uint32
	for i := range 16 {
		words[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	return words
}

// output is a node's output: enough to produce a chaining value or root bytes.
type output struct {
	inputCV [8]uint32
	block   [16]uint32
	counter uint64
	bLen    uint32
	flags   uint32
}

func (o output) chainingValue() [8]uint32 {
	full := compress(&o.inputCV, &o.block, o.counter, o.bLen, o.flags)
	var cv [8]uint32
	copy(cv[:], full[:8])
	return cv
}

func (o output) rootOutputInto(out []byte) {
	var counter uint64
	written := 0
	for written < len(out) {
		words := compress(&o.inputCV, &o.block, counter, o.bLen, o.flags|flagRoot)
		for _, w := range words {
			if written >= len(out) {
				break
			}
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], w)
			n := min(4, len(out)-written)
			copy(out[written:written+n], b[:n])
			written += n
		}
		counter++
	}
}

// chunkState absorbs one chunk block by block in fixed-size state.
type chunkState struct {
	cv               [8]uint32
	chunkCounter     uint64
	block            [blockBytes]byte
	blockLen         int
	blocksCompressed uint64
	flags            uint32
}

func newChunkState(key *[8]uint32, chunkCounter uint64, flags uint32) chunkState {
	return chunkState{cv: *key, chunkCounter: chunkCounter, flags: flags}
}

func (cs *chunkState) len() int { return blockBytes*int(cs.blocksCompressed) + cs.blockLen }

func (cs *chunkState) startFlag() uint32 {
	if cs.blocksCompressed == 0 {
		return chunkStart
	}
	return 0
}

func (cs *chunkState) update(input []byte) {
	for len(input) > 0 {
		if cs.blockLen == blockBytes {
			bw := wordsFromBlock(cs.block[:])
			out := compress(&cs.cv, &bw, cs.chunkCounter, blockBytes, cs.flags|cs.startFlag())
			copy(cs.cv[:], out[:8])
			cs.blocksCompressed++
			cs.block = [blockBytes]byte{}
			cs.blockLen = 0
		}
		take := min(blockBytes-cs.blockLen, len(input))
		copy(cs.block[cs.blockLen:], input[:take])
		cs.blockLen += take
		input = input[take:]
	}
}

func (cs *chunkState) output() output {
	return output{
		inputCV: cs.cv,
		block:   wordsFromBlock(cs.block[:cs.blockLen]),
		counter: cs.chunkCounter,
		bLen:    uint32(cs.blockLen),
		flags:   cs.flags | cs.startFlag() | chunkEnd,
	}
}

func parentOutput(left, right [8]uint32, key *[8]uint32, flags uint32) output {
	var block [16]uint32
	copy(block[:8], left[:])
	copy(block[8:], right[:])
	return output{inputCV: *key, block: block, counter: 0, bLen: blockBytes, flags: flags | flagParent}
}

func parentCV(left, right [8]uint32, key *[8]uint32, flags uint32) [8]uint32 {
	return parentOutput(left, right, key, flags).chainingValue()
}

// Hasher is an incremental BLAKE3 hash/MAC: a chunk-stack streaming hasher. It
// implements hash.Hash (32-byte output); FinalizeInto produces any length.
type Hasher struct {
	chunkState chunkState
	key        [8]uint32
	cvStack    [54][8]uint32 // BLAKE3's max input is 2^64 bytes -> depth <= 54
	cvStackLen int
	flags      uint32
}

// New starts an unkeyed hash.
func New() *Hasher { return newHasher(iv, 0) }

// NewKeyed starts a keyed MAC under a 32-byte key.
func NewKeyed(key *[32]byte) *Hasher {
	var kw [8]uint32
	for i := range 8 {
		kw[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	return newHasher(kw, keyedHash)
}

func newHasher(key [8]uint32, flags uint32) *Hasher {
	return &Hasher{chunkState: newChunkState(&key, 0, flags), key: key, flags: flags}
}

func (h *Hasher) pushStack(cv [8]uint32) {
	h.cvStack[h.cvStackLen] = cv
	h.cvStackLen++
}

func (h *Hasher) popStack() [8]uint32 {
	h.cvStackLen--
	return h.cvStack[h.cvStackLen]
}

func (h *Hasher) addChunkCV(newCV [8]uint32, totalChunks uint64) {
	for totalChunks&1 == 0 {
		newCV = parentCV(h.popStack(), newCV, &h.key, h.flags)
		totalChunks >>= 1
	}
	h.pushStack(newCV)
}

// Write feeds input bytes. Never returns an error.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if h.chunkState.len() == chunkBytes {
			chunkCV := h.chunkState.output().chainingValue()
			totalChunks := h.chunkState.chunkCounter + 1
			h.addChunkCV(chunkCV, totalChunks)
			h.chunkState = newChunkState(&h.key, totalChunks, h.flags)
		}
		take := min(chunkBytes-h.chunkState.len(), len(p))
		h.chunkState.update(p[:take])
		p = p[take:]
	}
	return n, nil
}

// FinalizeInto writes the digest into out (any length; an XOF for len > 32).
// It does not change the hasher state.
func (h *Hasher) FinalizeInto(out []byte) {
	o := h.chunkState.output()
	remaining := h.cvStackLen
	for remaining > 0 {
		remaining--
		o = parentOutput(h.cvStack[remaining], o.chainingValue(), &h.key, h.flags)
	}
	o.rootOutputInto(out)
}

// Sum appends the 32-byte digest to b without changing the hasher state.
func (h *Hasher) Sum(b []byte) []byte {
	out := make([]byte, 32)
	h.FinalizeInto(out)
	return append(b, out...)
}

// Reset returns the hasher to its just-constructed state.
func (h *Hasher) Reset() {
	h.chunkState = newChunkState(&h.key, 0, h.flags)
	h.cvStackLen = 0
}

// Size is 32 bytes (the standard BLAKE3 digest length).
func (h *Hasher) Size() int { return 32 }

// BlockSize is 64 bytes.
func (h *Hasher) BlockSize() int { return blockBytes }

var _ hash.Hash = (*Hasher)(nil)

// Sum256 is the one-shot 32-byte BLAKE3 hash of input.
func Sum256(input []byte) [32]byte {
	h := New()
	h.Write(input)
	var out [32]byte
	h.FinalizeInto(out[:])
	return out
}

// Hash writes the BLAKE3 hash of input into out (any length; an XOF for len > 32).
func Hash(out, input []byte) {
	h := New()
	h.Write(input)
	h.FinalizeInto(out)
}

// KeyedMAC writes the keyed BLAKE3 MAC of input into out.
func KeyedMAC(key *[32]byte, out, input []byte) {
	h := NewKeyed(key)
	h.Write(input)
	h.FinalizeInto(out)
}

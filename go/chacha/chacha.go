// Package chacha is a from-scratch ChaCha20 stream cipher (RFC 8439), verified
// against the RFC test vectors. Like Threefish it is a pure ARX design with no
// lookup tables. It is the cipher half of the ChaCha20-Poly1305 AEAD.
//
// This is the Go port of the dorado Rust crate's chacha module.
package chacha

import (
	"encoding/binary"
	"math/bits"
)

// The four ChaCha constants: the ASCII of "expand 32-byte k", little-endian.
var constants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

func quarterRound(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 16)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 12)
	s[a] += s[b]
	s[d] = bits.RotateLeft32(s[d]^s[a], 8)
	s[c] += s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], 7)
}

// Block produces one 64-byte keystream block for the key, 32-bit block counter,
// and 96-bit nonce.
func Block(key *[32]byte, counter uint32, nonce *[12]byte) [64]byte {
	var state [16]uint32
	copy(state[0:4], constants[:])
	for i := range 8 {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = counter
	for i := range 3 {
		state[13+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}

	working := state
	for range 10 {
		// Column rounds.
		quarterRound(&working, 0, 4, 8, 12)
		quarterRound(&working, 1, 5, 9, 13)
		quarterRound(&working, 2, 6, 10, 14)
		quarterRound(&working, 3, 7, 11, 15)
		// Diagonal rounds.
		quarterRound(&working, 0, 5, 10, 15)
		quarterRound(&working, 1, 6, 11, 12)
		quarterRound(&working, 2, 7, 8, 13)
		quarterRound(&working, 3, 4, 9, 14)
	}

	var out [64]byte
	for i := range 16 {
		binary.LittleEndian.PutUint32(out[i*4:], working[i]+state[i])
	}
	return out
}

// Apply XORs ChaCha20 keystream into data in place, starting at counter.
// Encryption and decryption are the same operation.
func Apply(key *[32]byte, counter uint32, nonce *[12]byte, data []byte) {
	var blk uint32
	for len(data) > 0 {
		ks := Block(key, counter+blk, nonce)
		n := min(len(data), 64)
		for j := range n {
			data[j] ^= ks[j]
		}
		data = data[n:]
		blk++
	}
}

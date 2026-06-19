// Package poly1305 is a from-scratch Poly1305 one-time MAC (RFC 8439), verified
// against the RFC test vectors. Arithmetic is modulo 2^130-5 in five 26-bit
// limbs (the standard reference representation).
//
// Poly1305 is a ONE-TIME MAC: each key must authenticate exactly one message.
// The Poly1305 type is incremental and fixed-size; MAC is the one-shot wrapper.
// This is the Go port of the dorado Rust crate's poly1305 module.
package poly1305

import "encoding/binary"

const mask26 uint32 = 0x3ffffff

// Poly1305 is incremental state. Feed bytes with Update, read the tag with
// Finalize.
type Poly1305 struct {
	r         [5]uint32 // clamped key r, as 26-bit limbs
	s         [4]uint32 // r1..r4 each times 5
	h         [5]uint32 // accumulator
	pad       [16]byte  // key's high half s
	buffer    [16]byte
	bufferLen int
}

// New starts a MAC under the 32-byte one-time key (r in the low 16 bytes, s in
// the high 16).
func New(key *[32]byte) *Poly1305 {
	t0 := binary.LittleEndian.Uint32(key[0:])
	t1 := binary.LittleEndian.Uint32(key[4:])
	t2 := binary.LittleEndian.Uint32(key[8:])
	t3 := binary.LittleEndian.Uint32(key[12:])
	r0 := t0 & 0x3ffffff
	r1 := ((t0 >> 26) | (t1 << 6)) & 0x3ffff03
	r2 := ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff
	r3 := ((t2 >> 14) | (t3 << 18)) & 0x3f03fff
	r4 := (t3 >> 8) & 0x00fffff
	p := &Poly1305{
		r: [5]uint32{r0, r1, r2, r3, r4},
		s: [4]uint32{r1 * 5, r2 * 5, r3 * 5, r4 * 5},
	}
	copy(p.pad[:], key[16:32])
	return p
}

// block absorbs one block of 1..16 bytes. A full 16-byte block adds 2^128; a
// shorter (final) block puts the 1 bit just past its last byte.
func (p *Poly1305) block(chunk []byte) {
	r0, r1, r2, r3, r4 := p.r[0], p.r[1], p.r[2], p.r[3], p.r[4]
	s1, s2, s3, s4 := p.s[0], p.s[1], p.s[2], p.s[3]
	h0, h1, h2, h3, h4 := p.h[0], p.h[1], p.h[2], p.h[3], p.h[4]

	var blk [17]byte
	copy(blk[:], chunk)
	blk[len(chunk)] = 1
	t0 := binary.LittleEndian.Uint32(blk[0:])
	t1 := binary.LittleEndian.Uint32(blk[4:])
	t2 := binary.LittleEndian.Uint32(blk[8:])
	t3 := binary.LittleEndian.Uint32(blk[12:])
	hibit := uint32(blk[16])

	h0 += t0 & mask26
	h1 += ((t0 >> 26) | (t1 << 6)) & mask26
	h2 += ((t1 >> 20) | (t2 << 12)) & mask26
	h3 += ((t2 >> 14) | (t3 << 18)) & mask26
	h4 += (t3 >> 8) | (hibit << 24)

	m := func(a, b uint32) uint64 { return uint64(a) * uint64(b) }
	d0 := m(h0, r0) + m(h1, s4) + m(h2, s3) + m(h3, s2) + m(h4, s1)
	d1 := m(h0, r1) + m(h1, r0) + m(h2, s4) + m(h3, s3) + m(h4, s2)
	d2 := m(h0, r2) + m(h1, r1) + m(h2, r0) + m(h3, s4) + m(h4, s3)
	d3 := m(h0, r3) + m(h1, r2) + m(h2, r1) + m(h3, r0) + m(h4, s4)
	d4 := m(h0, r4) + m(h1, r3) + m(h2, r2) + m(h3, r1) + m(h4, r0)

	c := uint32(d0 >> 26)
	h0 = uint32(d0) & mask26
	d1 += uint64(c)
	c = uint32(d1 >> 26)
	h1 = uint32(d1) & mask26
	d2 += uint64(c)
	c = uint32(d2 >> 26)
	h2 = uint32(d2) & mask26
	d3 += uint64(c)
	c = uint32(d3 >> 26)
	h3 = uint32(d3) & mask26
	d4 += uint64(c)
	c = uint32(d4 >> 26)
	h4 = uint32(d4) & mask26
	h0 += c * 5
	c = h0 >> 26
	h0 &= mask26
	h1 += c

	p.h = [5]uint32{h0, h1, h2, h3, h4}
}

// Update feeds message bytes. Full 16-byte blocks are absorbed immediately; a
// remainder is buffered until the next call or Finalize.
func (p *Poly1305) Update(data []byte) {
	if p.bufferLen > 0 {
		take := min(16-p.bufferLen, len(data))
		copy(p.buffer[p.bufferLen:], data[:take])
		p.bufferLen += take
		data = data[take:]
		if p.bufferLen < 16 {
			return
		}
		full := p.buffer
		p.block(full[:])
		p.bufferLen = 0
	}
	for len(data) >= 16 {
		p.block(data[:16])
		data = data[16:]
	}
	if len(data) > 0 {
		copy(p.buffer[:], data)
		p.bufferLen = len(data)
	}
}

// Finalize absorbs any buffered final block and returns the 16-byte tag.
func (p *Poly1305) Finalize() [16]byte {
	if p.bufferLen > 0 {
		buf := p.buffer
		p.block(buf[:p.bufferLen])
	}
	h0, h1, h2, h3, h4 := p.h[0], p.h[1], p.h[2], p.h[3], p.h[4]

	c := h1 >> 26
	h1 &= mask26
	h2 += c
	c = h2 >> 26
	h2 &= mask26
	h3 += c
	c = h3 >> 26
	h3 &= mask26
	h4 += c
	c = h4 >> 26
	h4 &= mask26
	h0 += c * 5
	c = h0 >> 26
	h0 &= mask26
	h1 += c

	// g = h - p (subtract 2^130-5); keep g if h >= p.
	g0 := h0 + 5
	c = g0 >> 26
	g0 &= mask26
	g1 := h1 + c
	c = g1 >> 26
	g1 &= mask26
	g2 := h2 + c
	c = g2 >> 26
	g2 &= mask26
	g3 := h3 + c
	c = g3 >> 26
	g3 &= mask26
	g4 := h4 + c - (1 << 26) // uint32 subtraction wraps

	mask := (g4 >> 31) - 1 // all-ones if h >= p (use g), else 0 (keep h)
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	nmask := ^mask
	h0 = (h0 & nmask) | g0
	h1 = (h1 & nmask) | g1
	h2 = (h2 & nmask) | g2
	h3 = (h3 & nmask) | g3
	h4 = (h4 & nmask) | g4

	// Pack the 26-bit limbs into 32-bit words.
	h0 |= h1 << 26
	h1 = (h1 >> 6) | (h2 << 20)
	h2 = (h2 >> 12) | (h3 << 14)
	h3 = (h3 >> 18) | (h4 << 8)

	// tag = (h + s) mod 2^128.
	f := uint64(h0) + uint64(binary.LittleEndian.Uint32(p.pad[0:]))
	h0 = uint32(f)
	f = uint64(h1) + uint64(binary.LittleEndian.Uint32(p.pad[4:])) + (f >> 32)
	h1 = uint32(f)
	f = uint64(h2) + uint64(binary.LittleEndian.Uint32(p.pad[8:])) + (f >> 32)
	h2 = uint32(f)
	f = uint64(h3) + uint64(binary.LittleEndian.Uint32(p.pad[12:])) + (f >> 32)
	h3 = uint32(f)

	var tag [16]byte
	binary.LittleEndian.PutUint32(tag[0:], h0)
	binary.LittleEndian.PutUint32(tag[4:], h1)
	binary.LittleEndian.PutUint32(tag[8:], h2)
	binary.LittleEndian.PutUint32(tag[12:], h3)
	return tag
}

// MAC computes the 16-byte Poly1305 tag of msg under the 32-byte one-time key.
func MAC(key *[32]byte, msg []byte) [16]byte {
	p := New(key)
	p.Update(msg)
	return p.Finalize()
}

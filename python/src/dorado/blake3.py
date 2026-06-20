"""From-scratch BLAKE3 hash and keyed MAC, using the streaming chunk-stack
algorithm: input is split into 1024-byte chunks, each compressed to a chaining
value, and chaining values are merged pairwise into a Merkle tree up to a single
root, holding only fixed-size state. Python port of the dorado Rust crate's blake3
module.
"""

from __future__ import annotations

import struct

_MASK32 = (1 << 32) - 1
_BLOCK_BYTES = 64
_CHUNK_BYTES = 1024

_CHUNK_START = 1 << 0
_CHUNK_END = 1 << 1
_FLAG_PARENT = 1 << 2
_FLAG_ROOT = 1 << 3
_KEYED_HASH = 1 << 4

_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

_MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _g(s: list[int], a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
    s[a] = (s[a] + s[b] + mx) & _MASK32
    s[d] = _rotr32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotr32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & _MASK32
    s[d] = _rotr32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotr32(s[b] ^ s[c], 7)


def _compress(cv, block, counter: int, b_len: int, flags: int) -> list[int]:
    state = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        _IV[0], _IV[1], _IV[2], _IV[3],
        counter & _MASK32, (counter >> 32) & _MASK32, b_len, flags,
    ]
    m = list(block)
    for rnd in range(7):
        _g(state, 0, 4, 8, 12, m[0], m[1])
        _g(state, 1, 5, 9, 13, m[2], m[3])
        _g(state, 2, 6, 10, 14, m[4], m[5])
        _g(state, 3, 7, 11, 15, m[6], m[7])
        _g(state, 0, 5, 10, 15, m[8], m[9])
        _g(state, 1, 6, 11, 12, m[10], m[11])
        _g(state, 2, 7, 8, 13, m[12], m[13])
        _g(state, 3, 4, 9, 14, m[14], m[15])
        if rnd < 6:
            m = [m[_MSG_PERMUTATION[i]] for i in range(16)]
    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= cv[i]
    return state


def _words_from_block(b: bytes) -> list[int]:
    padded = b + bytes(_BLOCK_BYTES - len(b))
    return list(struct.unpack("<16I", padded))


class _Output:
    __slots__ = ("input_cv", "block", "counter", "b_len", "flags")

    def __init__(self, input_cv, block, counter, b_len, flags):
        self.input_cv = input_cv
        self.block = block
        self.counter = counter
        self.b_len = b_len
        self.flags = flags

    def chaining_value(self) -> list[int]:
        return _compress(self.input_cv, self.block, self.counter, self.b_len, self.flags)[:8]

    def root_output(self, out_len: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < out_len:
            words = _compress(self.input_cv, self.block, counter, self.b_len, self.flags | _FLAG_ROOT)
            for w in words:
                if len(out) >= out_len:
                    break
                out += struct.pack("<I", w)[: min(4, out_len - len(out))]
            counter += 1
        return bytes(out[:out_len])


class _ChunkState:
    __slots__ = ("cv", "chunk_counter", "block", "block_len", "blocks_compressed", "flags")

    def __init__(self, key, chunk_counter: int, flags: int):
        self.cv = list(key)
        self.chunk_counter = chunk_counter
        self.block = bytearray(_BLOCK_BYTES)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def length(self) -> int:
        return _BLOCK_BYTES * self.blocks_compressed + self.block_len

    def _start_flag(self) -> int:
        return _CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, data: bytes) -> None:
        pos = 0
        end = len(data)
        while pos < end:
            if self.block_len == _BLOCK_BYTES:
                bw = _words_from_block(bytes(self.block))
                self.cv = _compress(self.cv, bw, self.chunk_counter, _BLOCK_BYTES, self.flags | self._start_flag())[:8]
                self.blocks_compressed += 1
                self.block = bytearray(_BLOCK_BYTES)
                self.block_len = 0
            take = min(_BLOCK_BYTES - self.block_len, end - pos)
            self.block[self.block_len : self.block_len + take] = data[pos : pos + take]
            self.block_len += take
            pos += take

    def output(self) -> _Output:
        return _Output(
            self.cv,
            _words_from_block(bytes(self.block[: self.block_len])),
            self.chunk_counter,
            self.block_len,
            self.flags | self._start_flag() | _CHUNK_END,
        )


def _parent_output(left, right, key, flags) -> _Output:
    return _Output(list(key), list(left) + list(right), 0, _BLOCK_BYTES, flags | _FLAG_PARENT)


def _parent_cv(left, right, key, flags) -> list[int]:
    return _parent_output(left, right, key, flags).chaining_value()


class Hasher:
    """An incremental BLAKE3 hash/MAC (chunk-stack streaming)."""

    def __init__(self, key: list[int], flags: int):
        self._key = key
        self._flags = flags
        self._chunk = _ChunkState(key, 0, flags)
        self._cv_stack: list[list[int]] = []

    @classmethod
    def new(cls) -> "Hasher":
        return cls(list(_IV), 0)

    @classmethod
    def new_keyed(cls, key32: bytes) -> "Hasher":
        if len(key32) != 32:
            raise ValueError("key must be 32 bytes")
        return cls(list(struct.unpack("<8I", key32)), _KEYED_HASH)

    def _add_chunk_cv(self, new_cv: list[int], total_chunks: int) -> None:
        while total_chunks & 1 == 0:
            new_cv = _parent_cv(self._cv_stack.pop(), new_cv, self._key, self._flags)
            total_chunks >>= 1
        self._cv_stack.append(new_cv)

    def update(self, data: bytes) -> "Hasher":
        pos = 0
        end = len(data)
        while pos < end:
            if self._chunk.length() == _CHUNK_BYTES:
                chunk_cv = self._chunk.output().chaining_value()
                total = self._chunk.chunk_counter + 1
                self._add_chunk_cv(chunk_cv, total)
                self._chunk = _ChunkState(self._key, total, self._flags)
            take = min(_CHUNK_BYTES - self._chunk.length(), end - pos)
            self._chunk.update(data[pos : pos + take])
            pos += take
        return self

    def digest(self, out_len: int = 32) -> bytes:
        out = self._chunk.output()
        for cv in reversed(self._cv_stack):
            out = _parent_output(cv, out.chaining_value(), self._key, self._flags)
        return out.root_output(out_len)


def hash(out_len: int, data: bytes) -> bytes:
    """One-shot BLAKE3 hash producing out_len bytes (an XOF for out_len > 32)."""
    return Hasher.new().update(data).digest(out_len)


def keyed_mac(key32: bytes, out_len: int, data: bytes) -> bytes:
    """One-shot keyed BLAKE3 MAC producing out_len bytes."""
    return Hasher.new_keyed(key32).update(data).digest(out_len)

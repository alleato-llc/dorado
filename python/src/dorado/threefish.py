"""From-scratch Threefish (256/512/1024-bit), the tweakable block cipher at the
core of Skein, following the Skein 1.3 specification (including the round-3 NIST
tweak to the key-schedule constant C240), plus CTR mode. Python port of the dorado
Rust crate; keys, tweaks, and blocks are little-endian.

Python ints are arbitrary precision, so the 64-bit ARX is done modulo 2**64 with an
explicit mask. Educational and unaudited.
"""

from __future__ import annotations

import struct

_MASK64 = (1 << 64) - 1
# Skein 1.3 key-schedule constant (the round-3 NIST value). Do not change.
_C240 = 0x1BD11BDAA9FC1A22

# Per-variant rotation and permutation tables (Skein 1.3). Verified against
# official test vectors and must not be changed.
_ROT256 = ((14, 52, 23, 5, 25, 46, 58, 32), (16, 57, 40, 37, 33, 12, 22, 32))
_PERM256 = (0, 3, 2, 1)

_ROT512 = (
    (46, 33, 17, 44, 39, 13, 25, 8),
    (36, 27, 49, 9, 30, 50, 29, 35),
    (19, 14, 36, 54, 34, 10, 39, 56),
    (37, 42, 39, 56, 24, 17, 43, 22),
)
_PERM512 = (2, 1, 4, 7, 6, 5, 0, 3)

_ROT1024 = (
    (24, 38, 33, 5, 41, 16, 31, 9),
    (13, 19, 4, 20, 9, 34, 44, 48),
    (8, 10, 51, 48, 37, 56, 47, 35),
    (47, 55, 13, 41, 31, 51, 46, 52),
    (8, 49, 34, 47, 12, 4, 19, 23),
    (17, 18, 41, 28, 47, 53, 42, 31),
    (22, 23, 59, 16, 44, 42, 44, 37),
    (37, 52, 17, 25, 30, 41, 25, 20),
)
_PERM1024 = (0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & _MASK64


class Threefish:
    """One Threefish variant: encrypt/decrypt a single block, or run CTR."""

    def __init__(self, key: bytes, tweak: bytes, nw: int, rounds: int, rot, perm):
        self.nw = nw
        self.rounds = rounds
        self.rot = rot
        self.perm = perm
        self.block_bytes = nw * 8
        if len(key) != self.block_bytes:
            raise ValueError(f"key must be {self.block_bytes} bytes, got {len(key)}")
        if len(tweak) != 16:
            raise ValueError(f"tweak must be 16 bytes, got {len(tweak)}")
        words = list(struct.unpack(f"<{nw}Q", key))
        parity = _C240
        for w in words:
            parity ^= w
        self.ek = words + [parity & _MASK64]
        t0, t1 = struct.unpack("<2Q", tweak)
        self.et = (t0, t1, t0 ^ t1)

    @classmethod
    def t256(cls, key: bytes, tweak: bytes) -> "Threefish":
        return cls(key, tweak, 4, 72, _ROT256, _PERM256)

    @classmethod
    def t512(cls, key: bytes, tweak: bytes) -> "Threefish":
        return cls(key, tweak, 8, 72, _ROT512, _PERM512)

    @classmethod
    def t1024(cls, key: bytes, tweak: bytes) -> "Threefish":
        return cls(key, tweak, 16, 80, _ROT1024, _PERM1024)

    def _add_subkey(self, s: int, state: list[int]) -> None:
        nw = self.nw
        for i in range(nw):
            k = self.ek[(s + i) % (nw + 1)]
            if i == nw - 3:
                k = (k + self.et[s % 3]) & _MASK64
            elif i == nw - 2:
                k = (k + self.et[(s + 1) % 3]) & _MASK64
            elif i == nw - 1:
                k = (k + s) & _MASK64
            state[i] = (state[i] + k) & _MASK64

    def _sub_subkey(self, s: int, state: list[int]) -> None:
        nw = self.nw
        for i in range(nw):
            k = self.ek[(s + i) % (nw + 1)]
            if i == nw - 3:
                k = (k + self.et[s % 3]) & _MASK64
            elif i == nw - 2:
                k = (k + self.et[(s + 1) % 3]) & _MASK64
            elif i == nw - 1:
                k = (k + s) & _MASK64
            state[i] = (state[i] - k) & _MASK64

    def _encrypt_state(self, state: list[int]) -> None:
        nw = self.nw
        rot = self.rot
        perm = self.perm
        for r in range(self.rounds):
            if r % 4 == 0:
                self._add_subkey(r // 4, state)
            for j in range(nw // 2):
                x0 = state[2 * j]
                x1 = state[2 * j + 1]
                y0 = (x0 + x1) & _MASK64
                y1 = _rotl(x1, rot[j][r % 8]) ^ y0
                state[2 * j] = y0
                state[2 * j + 1] = y1
            state[:] = [state[perm[i]] for i in range(nw)]
        self._add_subkey(self.rounds // 4, state)

    def _decrypt_state(self, state: list[int]) -> None:
        nw = self.nw
        rot = self.rot
        perm = self.perm
        self._sub_subkey(self.rounds // 4, state)
        for r in range(self.rounds - 1, -1, -1):
            unpermuted = [0] * nw
            for i in range(nw):
                unpermuted[perm[i]] = state[i]
            state[:] = unpermuted
            for j in range(nw // 2):
                y0 = state[2 * j]
                y1 = state[2 * j + 1]
                x1 = _rotr(y1 ^ y0, rot[j][r % 8])
                x0 = (y0 - x1) & _MASK64
                state[2 * j] = x0
                state[2 * j + 1] = x1
            if r % 4 == 0:
                self._sub_subkey(r // 4, state)

    def encrypt_block(self, block: bytes) -> bytes:
        state = list(struct.unpack(f"<{self.nw}Q", block))
        self._encrypt_state(state)
        return struct.pack(f"<{self.nw}Q", *state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = list(struct.unpack(f"<{self.nw}Q", block))
        self._decrypt_state(state)
        return struct.pack(f"<{self.nw}Q", *state)

    def new_ctr(self, iv: bytes) -> "Ctr":
        """Start a resumable CTR keystream from iv (the initial big-endian counter)."""
        return Ctr(self, iv)

    def ctr_apply(self, iv: bytes, data: bytes) -> bytes:
        """Apply CTR over the whole buffer (encrypt == decrypt), returning bytes."""
        buf = bytearray(data)
        self.new_ctr(iv).apply(buf)
        return bytes(buf)


class Ctr:
    """A resumable CTR keystream: apply() may be called per chunk, the counter
    carrying across calls, so a file streams in constant memory and stays identical
    to whole-file CTR (non-final chunks are whole blocks)."""

    def __init__(self, cipher: Threefish, iv: bytes):
        if len(iv) != cipher.block_bytes:
            raise ValueError(f"iv must be {cipher.block_bytes} bytes, got {len(iv)}")
        self._cipher = cipher
        self._counter = bytearray(iv)

    def apply(self, buf: bytearray) -> None:
        """XOR the keystream into buf in place (encrypt == decrypt)."""
        bs = self._cipher.block_bytes
        for off in range(0, len(buf), bs):
            ks = self._cipher.encrypt_block(bytes(self._counter))
            n = min(bs, len(buf) - off)
            chunk = int.from_bytes(buf[off : off + n], "big")
            mask = int.from_bytes(ks[:n], "big")
            buf[off : off + n] = (chunk ^ mask).to_bytes(n, "big")
            self._increment()

    def _increment(self) -> None:
        c = self._counter
        for i in range(len(c) - 1, -1, -1):
            c[i] = (c[i] + 1) & 0xFF
            if c[i] != 0:
                break

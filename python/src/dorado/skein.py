"""From-scratch Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI
(Unique Block Iteration), the hash function Threefish was designed to power. The
output length is chosen per call. Python port of the dorado Rust crate's skein
module. Streams via the incremental Skein512 class; one-shot helpers wrap it.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

from .threefish import Threefish

_BLOCK = 64

# UBI block type values (the 6-bit type field of the tweak).
_T_KEY = 0
_T_CFG = 4
_T_MSG = 48
_T_OUT = 63


def _tweak(position: int, ty: int, first: bool, last: bool) -> bytes:
    t1 = ty << 56
    if first:
        t1 |= 1 << 62
    if last:
        t1 |= 1 << 63
    return struct.pack("<QQ", position, t1)


def _ubi(g: bytearray, msg: bytes, ty: int) -> None:
    total = len(msg)
    offset = 0
    position = 0
    first = True
    while True:
        take = min(total - offset, _BLOCK)
        block = msg[offset : offset + take] + bytes(_BLOCK - take)
        position += take
        offset += take
        last = offset >= total
        enc = Threefish.t512(bytes(g), _tweak(position, ty, first, last)).encrypt_block(block)
        for i in range(_BLOCK):
            g[i] = enc[i] ^ block[i]
        first = False
        if last:
            break


def _config_block(out_bits: int) -> bytes:
    c = bytearray(32)
    c[0:4] = b"SHA3"
    c[4] = 1  # version 1 (16-bit little-endian)
    struct.pack_into("<Q", c, 8, out_bits)
    return bytes(c)


def _output_into(g: bytes, out_len: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        block = bytearray(g)
        _ubi(block, struct.pack("<Q", counter), _T_OUT)
        out += block[: min(_BLOCK, out_len - len(out))]
        counter += 1
    return bytes(out[:out_len])


class Skein512:
    """Incremental Skein-512 hash or MAC, holding back the final block until done."""

    def __init__(self, out_len: int, key: bytes = b""):
        self._out_len = out_len
        g = bytearray(64)
        if key:
            _ubi(g, key, _T_KEY)
        _ubi(g, _config_block(out_len * 8), _T_CFG)
        self._g = g
        self._buffer = bytearray()
        self._position = 0
        self._first = True

    def _commit(self, block: bytes, nbytes: int, last: bool) -> None:
        self._position += nbytes
        enc = Threefish.t512(bytes(self._g), _tweak(self._position, _T_MSG, self._first, last)).encrypt_block(block)
        for i in range(_BLOCK):
            self._g[i] = enc[i] ^ block[i]
        self._first = False

    def update(self, data: bytes) -> "Skein512":
        self._buffer += data
        # Process all but the final (possibly partial) block; only finalize knows last.
        while len(self._buffer) > _BLOCK:
            self._commit(bytes(self._buffer[:_BLOCK]), _BLOCK, False)
            del self._buffer[:_BLOCK]
        return self

    def digest(self) -> bytes:
        g_save = bytearray(self._g)
        pos_save = self._position
        first_save = self._first
        block = bytes(self._buffer) + bytes(_BLOCK - len(self._buffer))
        self._commit(block, len(self._buffer), True)
        out = _output_into(bytes(self._g), self._out_len)
        # Restore so update() may continue after a digest().
        self._g = g_save
        self._position = pos_save
        self._first = first_save
        return out


def hash(out_len: int, msg: bytes) -> bytes:
    """One-shot Skein-512 hash of msg producing out_len bytes."""
    return Skein512(out_len).update(msg).digest()


def mac(key: bytes, out_len: int, msg: bytes) -> bytes:
    """One-shot Skein-512 keyed MAC producing out_len bytes (key absorbed first)."""
    return Skein512(out_len, key).update(msg).digest()


def hash_stream(out_len: int, reader: BinaryIO, buf_size: int = 64 * 1024) -> bytes:
    """Stream-hash a file-like object in constant memory."""
    h = Skein512(out_len)
    while True:
        chunk = reader.read(buf_size)
        if not chunk:
            break
        h.update(chunk)
    return h.digest()

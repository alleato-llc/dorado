"""The construction over the Threefish cipher: the authenticated chunked password
container, raw CTR, and inspect. Streams over binary file-like objects in constant
memory (files larger than RAM are fine), matching the Rust reference; in-memory
``bytes`` wrappers are provided. The on-disk output is byte-for-byte identical to
the other ports, so ``.mahi`` files are cross-compatible.

This is an SDK; a CLI is in ``dorado.cli``. Educational and unaudited.
"""

from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from typing import BinaryIO, Optional

from . import format as fmt, kdf as kdf_mod, mac as mac_mod
from .errors import DoradoError
from .format import KdfParams
from .threefish import Threefish

_FRAME_DOMAIN = b"DRDOchnk"
_RAW_BUF = 64 * 1024


@dataclass
class PasswordOptions:
    variant: int = fmt.T256
    kdf: KdfParams = field(default_factory=lambda: KdfParams.argon2id(64 * 1024, 3, 1))
    mac: int = fmt.MAC_SKEIN
    tweak: bytes = b"\x00" * 16
    chunk_size: int = fmt.DEFAULT_CHUNK_BYTES
    label: bytes = b""


@dataclass
class ContainerInfo:
    version: int
    variant: int
    kdf: KdfParams
    mac: int
    chunk_size: int
    salt_len: int
    tweak: bytes
    label: bytes


def default_options() -> PasswordOptions:
    """Threefish-256, Argon2id, Skein-512 MAC, 64 KiB chunks."""
    return PasswordOptions()


def _cipher(variant: int, key: bytes, tweak: bytes) -> Threefish:
    if variant == fmt.T256:
        return Threefish.t256(key, tweak)
    if variant == fmt.T512:
        return Threefish.t512(key, tweak)
    if variant == fmt.T1024:
        return Threefish.t1024(key, tweak)
    raise ValueError(f"unknown variant {variant}")


def _frame_aad(header_bytes: bytes, index: int, is_last: bool, ct: bytes) -> bytes:
    parts = [_FRAME_DOMAIN]
    if index == 0:
        parts.append(header_bytes)
    parts.append(struct.pack(">Q", index))
    parts.append(bytes([1 if is_last else 0]))
    parts.append(struct.pack(">I", len(ct)))
    parts.append(ct)
    return b"".join(parts)


def _write_frame(writer: BinaryIO, is_last: bool, ct: bytes, tag: bytes) -> None:
    writer.write(bytes([1 if is_last else 0]) + struct.pack(">I", len(ct)) + ct + tag)


def encrypt_password_stream(password: bytes, opts: PasswordOptions, reader: BinaryIO, writer: BinaryIO) -> None:
    """Encrypt reader into writer as an authenticated password container."""
    if len(opts.label) > fmt.MAX_LABEL_LEN:
        raise DoradoError(f"label too long ({len(opts.label)} bytes)")
    v = opts.variant
    bl = fmt.block_len(v)
    if opts.chunk_size <= 0 or opts.chunk_size > fmt.MAX_CHUNK_BYTES or opts.chunk_size % bl != 0:
        raise ValueError(f"chunk size must be a positive multiple of {bl}")
    salt = os.urandom(16)
    iv = os.urandom(bl)
    keymat = kdf_mod.derive(opts.kdf, password, salt, fmt.key_len(v) + fmt.MAC_KEY_LEN)
    enc_key, mac_key = keymat[: fmt.key_len(v)], keymat[fmt.key_len(v):]

    header = fmt.Header(fmt.VERSION, v, opts.kdf, opts.mac, opts.chunk_size, salt, opts.tweak, iv, opts.label)
    header_bytes = fmt.marshal(header)

    ctr = _cipher(v, enc_key, opts.tweak).new_ctr(iv)
    writer.write(header_bytes)

    current = fmt.read_full(reader, opts.chunk_size)
    index = 0
    while True:
        nxt = fmt.read_full(reader, opts.chunk_size)
        is_last = len(nxt) == 0
        chunk = bytearray(current)
        ctr.apply(chunk)
        chunk = bytes(chunk)
        tag = mac_mod.tag(opts.mac, mac_key, _frame_aad(header_bytes, index, is_last, chunk))
        _write_frame(writer, is_last, chunk, tag)
        if is_last:
            break
        index += 1
        current = nxt


def _read_frame(reader: BinaryIO, chunk_size: int):
    head = fmt.read_full(reader, 5)
    if len(head) == 0:
        raise DoradoError("stream ended before the final chunk (truncated)")
    if len(head) < 5:
        raise DoradoError("incomplete frame header (truncated)")
    flag = head[0]
    if flag > 1:
        raise DoradoError(f"invalid frame flag {flag}")
    is_last = flag == 1
    ct_len = struct.unpack(">I", head[1:5])[0]
    if ct_len > chunk_size:
        raise DoradoError("frame length exceeds the header chunk size")
    ct = fmt.read_full(reader, ct_len)
    if len(ct) != ct_len:
        raise DoradoError("truncated frame ciphertext")
    tag = fmt.read_full(reader, fmt.TAG_LEN)
    if len(tag) != fmt.TAG_LEN:
        raise DoradoError("truncated frame tag")
    return is_last, ct, tag


def decrypt_password_stream(
    password: bytes, reader: BinaryIO, writer: BinaryIO, expected_label: Optional[bytes] = None
) -> None:
    """Decrypt an authenticated password container from reader into writer. If
    expected_label is not None, the container's label must equal it."""
    h = fmt.read(reader)
    if expected_label is not None and expected_label != h.label:
        raise DoradoError("container label does not match the expected label")
    header_bytes = fmt.marshal(h)
    bl = fmt.block_len(h.variant)
    if h.chunk_size == 0 or h.chunk_size > fmt.MAX_CHUNK_BYTES or h.chunk_size % bl != 0:
        raise DoradoError(f"invalid chunk size {h.chunk_size} in header")
    kdf_mod.validate(h.kdf)

    keymat = kdf_mod.derive(h.kdf, password, h.salt, fmt.key_len(h.variant) + fmt.MAC_KEY_LEN)
    enc_key, mac_key = keymat[: fmt.key_len(h.variant)], keymat[fmt.key_len(h.variant):]

    ctr = _cipher(h.variant, enc_key, h.tweak).new_ctr(h.iv)
    index = 0
    while True:
        is_last, ct, tag = _read_frame(reader, h.chunk_size)
        if not mac_mod.verify(h.mac, mac_key, _frame_aad(header_bytes, index, is_last, ct), tag):
            raise DoradoError("authentication failed (wrong password, corruption, or tampering)")
        plain = bytearray(ct)
        ctr.apply(plain)
        writer.write(bytes(plain))
        if is_last:
            break
        if len(ct) != h.chunk_size:
            raise DoradoError("non-final chunk is not full size")
        index += 1


def raw_ctr_stream(variant: int, key: bytes, tweak: bytes, iv: bytes, reader: BinaryIO, writer: BinaryIO) -> None:
    """Apply bare, unauthenticated CTR with a user-supplied key and IV, streaming."""
    bl = fmt.block_len(variant)
    if len(iv) != bl:
        raise ValueError(f"iv must be {bl} bytes, got {len(iv)}")
    ctr = _cipher(variant, key, tweak).new_ctr(iv)
    buf_size = (_RAW_BUF // bl) * bl
    while True:
        data = fmt.read_full(reader, buf_size)
        if not data:
            break
        buf = bytearray(data)
        ctr.apply(buf)
        writer.write(bytes(buf))
        if len(data) < buf_size:
            break


def inspect_stream(reader: BinaryIO) -> ContainerInfo:
    """Read and describe a container's header without decrypting it."""
    h = fmt.read(reader)
    return ContainerInfo(h.version, h.variant, h.kdf, h.mac, h.chunk_size, len(h.salt), h.tweak, h.label)


# ---- in-memory convenience wrappers ----


def encrypt_password(password: bytes, opts: PasswordOptions, plaintext: bytes) -> bytes:
    out = io.BytesIO()
    encrypt_password_stream(password, opts, io.BytesIO(plaintext), out)
    return out.getvalue()


def decrypt_password(password: bytes, data: bytes, expected_label: Optional[bytes] = None) -> bytes:
    out = io.BytesIO()
    decrypt_password_stream(password, io.BytesIO(data), out, expected_label)
    return out.getvalue()


def inspect(data: bytes) -> ContainerInfo:
    return inspect_stream(io.BytesIO(data))


def raw_ctr(variant: int, key: bytes, tweak: bytes, iv: bytes, data: bytes) -> bytes:
    out = io.BytesIO()
    raw_ctr_stream(variant, key, tweak, iv, io.BytesIO(data), out)
    return out.getvalue()

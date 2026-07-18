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

from . import format as fmt, kdf as kdf_mod, mac as mac_mod, skein
from .errors import AuthError, InvalidParams, MalformedContainer
from .format import KdfParams
from .threefish import Threefish

_FRAME_DOMAIN = b"DRDOchnk"
_RAW_BUF = 64 * 1024

# Raw-key authenticated mode (encrypt-then-MAC, caller-supplied key, no password,
# no KDF). See ../../../docs/spec.md, "Raw-key modes".
_RAW_AUTH_ENC_DOMAIN = b"DRDOrawE"
_RAW_AUTH_MAC_DOMAIN = b"DRDOrawM"
_RAW_FRAME_DOMAIN = b"DRDOrwFr"


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
    raise InvalidParams(f"unknown variant {variant}")


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
        raise InvalidParams(f"label too long ({len(opts.label)} bytes)")
    v = opts.variant
    bl = fmt.block_len(v)
    if opts.chunk_size <= 0 or opts.chunk_size > fmt.effective_max_chunk_bytes() or opts.chunk_size % bl != 0:
        raise InvalidParams(f"chunk size must be a positive multiple of {bl}")
    salt = os.urandom(16)
    iv = os.urandom(bl)
    keymat = kdf_mod.derive(opts.kdf, password, salt, fmt.key_len(v) + fmt.MAC_KEY_LEN)
    enc_key, mac_key = keymat[: fmt.key_len(v)], keymat[fmt.key_len(v):]
    # Best-effort zeroization is fundamentally limited in Python: keymat and the key
    # slices are immutable bytes and cannot be wiped, and the KDF and slicing make
    # extra copies the GC frees on its own schedule. There is nothing safe to clear
    # here without contorting the code, so we accept the limitation.

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
        raise MalformedContainer("stream ended before the final chunk (truncated)")
    if len(head) < 5:
        raise MalformedContainer("incomplete frame header (truncated)")
    flag = head[0]
    if flag > 1:
        raise MalformedContainer(f"invalid frame flag {flag}")
    is_last = flag == 1
    ct_len = struct.unpack(">I", head[1:5])[0]
    if ct_len > chunk_size:
        raise MalformedContainer("frame length exceeds the header chunk size")
    ct = fmt.read_full(reader, ct_len)
    if len(ct) != ct_len:
        raise MalformedContainer("truncated frame ciphertext")
    tag = fmt.read_full(reader, fmt.TAG_LEN)
    if len(tag) != fmt.TAG_LEN:
        raise MalformedContainer("truncated frame tag")
    return is_last, ct, tag


def decrypt_password_stream(
    password: bytes, reader: BinaryIO, writer: BinaryIO, expected_label: Optional[bytes] = None
) -> None:
    """Decrypt an authenticated password container from reader into writer. If
    expected_label is not None, the container's label must equal it."""
    h = fmt.read(reader)
    if expected_label is not None and expected_label != h.label:
        raise MalformedContainer("container label does not match the expected label")
    header_bytes = fmt.marshal(h)
    bl = fmt.block_len(h.variant)
    if h.chunk_size == 0 or h.chunk_size > fmt.effective_max_chunk_bytes() or h.chunk_size % bl != 0:
        raise MalformedContainer(f"invalid chunk size {h.chunk_size} in header")
    kdf_mod.validate(h.kdf)

    keymat = kdf_mod.derive(h.kdf, password, h.salt, fmt.key_len(h.variant) + fmt.MAC_KEY_LEN)
    enc_key, mac_key = keymat[: fmt.key_len(h.variant)], keymat[fmt.key_len(h.variant):]
    # See the note in encrypt_password_stream: these keys are immutable bytes and
    # cannot be reliably wiped from memory in Python. Best-effort zeroization is not
    # achievable here without contorting the code.

    ctr = _cipher(h.variant, enc_key, h.tweak).new_ctr(h.iv)
    index = 0
    while True:
        is_last, ct, tag = _read_frame(reader, h.chunk_size)
        if not mac_mod.verify(h.mac, mac_key, _frame_aad(header_bytes, index, is_last, ct), tag):
            raise AuthError("authentication failed (wrong password, corruption, or tampering)")
        plain = bytearray(ct)
        ctr.apply(plain)
        writer.write(bytes(plain))
        if is_last:
            break
        if len(ct) != h.chunk_size:
            raise MalformedContainer("non-final chunk is not full size")
        index += 1


def raw_ctr_stream(variant: int, key: bytes, tweak: bytes, iv: bytes, reader: BinaryIO, writer: BinaryIO) -> None:
    """Apply bare, unauthenticated CTR with a user-supplied key and IV, streaming."""
    bl = fmt.block_len(variant)
    if len(iv) != bl:
        raise InvalidParams(f"iv must be {bl} bytes, got {len(iv)}")
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


def _split_raw_key(variant: int, key: bytes) -> tuple[bytes, bytes]:
    """Split a caller-supplied raw key into an independent encryption subkey and MAC
    subkey via domain-separated Skein-512 keyed hashing (key is the MAC key, the
    domain label is the message). Not a password KDF: key is assumed to already be
    high-entropy, so no cost-parameterized stretching is applied, only separation
    into two subkeys that must not be the same bytes used for two different
    primitives."""
    kl = fmt.key_len(variant)
    if len(key) != kl:
        raise InvalidParams(f"raw key must be {kl} bytes for this variant, got {len(key)}")
    enc_key = skein.mac(key, kl, _RAW_AUTH_ENC_DOMAIN)
    mac_key = skein.mac(key, fmt.MAC_KEY_LEN, _RAW_AUTH_MAC_DOMAIN)
    return enc_key, mac_key


def _raw_frame_aad(tweak: bytes, iv: bytes, index: int, is_last: bool, ct: bytes) -> bytes:
    """AAD for a raw-authenticated frame: a domain separator, the tweak and IV (for
    the first frame only, binding the parameters — raw mode has no header to bind
    them into the way the password container does), the frame index, the last
    flag, and the ciphertext. Mirrors _frame_aad, substituting tweak+iv for the
    header."""
    parts = [_RAW_FRAME_DOMAIN]
    if index == 0:
        parts.append(tweak)
        parts.append(iv)
    parts.append(struct.pack(">Q", index))
    parts.append(bytes([1 if is_last else 0]))
    parts.append(struct.pack(">I", len(ct)))
    parts.append(ct)
    return b"".join(parts)


def _validate_raw_auth_params(variant: int, iv: bytes, chunk_size: int) -> None:
    bl = fmt.block_len(variant)
    if len(iv) != bl:
        raise InvalidParams(f"iv must be {bl} bytes for this variant, got {len(iv)}")
    if chunk_size <= 0 or chunk_size % bl != 0:
        raise InvalidParams(f"chunk size must be a positive multiple of the block size ({bl}), got {chunk_size}")


def encrypt_raw_authenticated_stream(
    variant: int, key: bytes, tweak: bytes, iv: bytes, mac: int, chunk_size: int, reader: BinaryIO, writer: BinaryIO
) -> None:
    """Stream authenticated CTR with a caller-supplied key: encrypt-then-MAC, no
    password, no KDF (see _split_raw_key). Data streams in fixed-size authenticated
    chunks, reusing the same frame construction as the password container
    (_raw_frame_aad/_write_frame/_read_frame), so truncation, reordering, and
    dropped chunks are all rejected on decryption exactly as they are there. There
    is no header: the caller must supply the same variant, tweak, iv, mac, and
    chunk_size on decrypt as were used to encrypt, and remember them out of band."""
    _validate_raw_auth_params(variant, iv, chunk_size)
    enc_key, mac_key = _split_raw_key(variant, key)
    ctr = _cipher(variant, enc_key, tweak).new_ctr(iv)

    current = fmt.read_full(reader, chunk_size)
    index = 0
    while True:
        nxt = fmt.read_full(reader, chunk_size)
        is_last = len(nxt) == 0
        chunk = bytearray(current)
        ctr.apply(chunk)
        chunk = bytes(chunk)
        tag = mac_mod.tag(mac, mac_key, _raw_frame_aad(tweak, iv, index, is_last, chunk))
        _write_frame(writer, is_last, chunk, tag)
        if is_last:
            break
        index += 1
        current = nxt


def decrypt_raw_authenticated_stream(
    variant: int, key: bytes, tweak: bytes, iv: bytes, mac: int, chunk_size: int, reader: BinaryIO, writer: BinaryIO
) -> None:
    """Decrypt an encrypt_raw_authenticated_stream stream. Each frame's tag is
    verified in constant time before that frame is decrypted, so a wrong key or a
    corrupted or tampered stream raises AuthError instead of silently producing
    garbage or attacker-influenced plaintext -- the failure mode raw_ctr_stream
    cannot detect."""
    _validate_raw_auth_params(variant, iv, chunk_size)
    if chunk_size > fmt.effective_max_chunk_bytes():
        raise InvalidParams(f"chunk size {chunk_size} exceeds the accepted maximum")
    enc_key, mac_key = _split_raw_key(variant, key)
    ctr = _cipher(variant, enc_key, tweak).new_ctr(iv)

    index = 0
    while True:
        is_last, ct, tag = _read_frame(reader, chunk_size)
        if not mac_mod.verify(mac, mac_key, _raw_frame_aad(tweak, iv, index, is_last, ct), tag):
            raise AuthError("authentication failed (wrong key, corruption, or tampering)")
        plain = bytearray(ct)
        ctr.apply(plain)
        writer.write(bytes(plain))
        if is_last:
            break
        if len(ct) != chunk_size:
            raise MalformedContainer("non-final chunk is not full size")
        index += 1


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


def encrypt_raw_authenticated(
    variant: int, key: bytes, tweak: bytes, iv: bytes, mac: int, chunk_size: int, plaintext: bytes
) -> bytes:
    out = io.BytesIO()
    encrypt_raw_authenticated_stream(variant, key, tweak, iv, mac, chunk_size, io.BytesIO(plaintext), out)
    return out.getvalue()


def decrypt_raw_authenticated(
    variant: int, key: bytes, tweak: bytes, iv: bytes, mac: int, chunk_size: int, data: bytes
) -> bytes:
    out = io.BytesIO()
    decrypt_raw_authenticated_stream(variant, key, tweak, iv, mac, chunk_size, io.BytesIO(data), out)
    return out.getvalue()

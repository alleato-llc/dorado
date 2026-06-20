"""The MAC menu: Skein-512 (default) and keyed BLAKE3 from this project's
from-scratch hashes, HMAC-SHA256 from the standard library. All three take the
32-byte MAC key and produce a 32-byte tag.
"""

from __future__ import annotations

import hashlib
import hmac

from . import blake3, format as fmt, skein


def tag(mac_id: int, mac_key: bytes, signed: bytes) -> bytes:
    """Compute a 32-byte tag over signed under the selected MAC."""
    if mac_id == fmt.MAC_SKEIN:
        return skein.mac(mac_key, fmt.TAG_LEN, signed)
    if mac_id == fmt.MAC_BLAKE3:
        return blake3.keyed_mac(mac_key, fmt.TAG_LEN, signed)
    if mac_id == fmt.MAC_HMAC:
        return hmac.new(mac_key, signed, hashlib.sha256).digest()
    raise ValueError(f"unknown mac id {mac_id}")


def verify(mac_id: int, mac_key: bytes, signed: bytes, received: bytes) -> bool:
    """Recompute the tag and compare it in constant time."""
    return hmac.compare_digest(tag(mac_id, mac_key, signed), received)

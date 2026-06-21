"""Exceptions for the dorado container."""

from __future__ import annotations


class DoradoError(Exception):
    """A malformed, unsupported, or failed-authentication container: bad magic or
    version, truncation, hostile KDF parameters, a label mismatch, or a MAC
    verification failure. This stays the catch-all base; the subclasses below give
    callers a coarse category without breaking existing ``except DoradoError``."""


class AuthError(DoradoError):
    """Authentication failed while decrypting: a wrong password, corruption, or
    tampering. These three cases are deliberately not distinguished (same exception
    and message) so an attacker cannot tell them apart."""


class MalformedContainer(DoradoError):
    """The container bytes are malformed, truncated, or unsupported before any MAC
    check: bad magic, an unsupported version, a truncated header or frame, an invalid
    frame flag, an oversized frame, an unknown KDF/MAC/PRF id, a label that is too
    long, a hostile chunk size in the header, hostile KDF cost parameters, or a label
    mismatch."""


class InvalidParams(DoradoError):
    """A caller-supplied parameter is invalid: a bad chunk size on encrypt, an unknown
    variant/KDF/MAC id on the build side, or a bad hex/tweak/IV/key length."""

"""Exceptions for the dorado container."""

from __future__ import annotations


class DoradoError(Exception):
    """A malformed, unsupported, or failed-authentication container: bad magic or
    version, truncation, hostile KDF parameters, a label mismatch, or a MAC
    verification failure."""

"""Backwards-compatible module for the async keystore.

Historically some call sites imported `AsyncKeyStore` from `johnnycanencrypt.async_keystore`.
The implementation now lives in `johnnycanencrypt.async_db.keystore`.
"""

from __future__ import annotations

from .async_db.keystore import AsyncKeyStore

__all__ = ["AsyncKeyStore"]

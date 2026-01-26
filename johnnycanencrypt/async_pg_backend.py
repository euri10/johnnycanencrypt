"""Backwards-compatible module for AsyncPgBackend.

The implementation moved to `johnnycanencrypt.async_db.pg_backend.AsyncPgBackend`.
This shim keeps import paths working:

    from johnnycanencrypt.async_pg_backend import AsyncPgBackend
"""

from __future__ import annotations

from .async_db.pg_backend import AsyncPgBackend

__all__ = ["AsyncPgBackend"]

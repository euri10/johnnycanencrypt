"""Async API surface for the keystore.

This is introduced to support async PostgreSQL drivers (asyncpg) without forcing
existing synchronous users (`KeyStore`) into event loop management.

The initial goal is schema initialization and connectivity.
Full key CRUD parity will be implemented incrementally.
"""

from __future__ import annotations

import os

from pathlib import Path
from typing import Union

from .pg_backend import AsyncPgBackend
from ..db.backend import load_db_config

StrOrBytesPath = Union[str, bytes, os.PathLike]


class AsyncKeyStore:
    """Async keystore API (parity with KeyStore).

    Currently supports:
    - Postgres connection acquisition via asyncpg
    - Schema initialization for a fresh database

    Configuration is environment-driven, same as KeyStore.
    """

    def __init__(self, path: StrOrBytesPath) -> None:
        # Parity with KeyStore __init__
        if isinstance(path, str):
            fullpath = Path(path).absolute()
        elif isinstance(path, bytes):
            fullpath = Path(path.decode("utf-8")).absolute()
        elif isinstance(path, os.PathLike):
            fullpath = Path(path).absolute()
        else:
            # Fall back: try Path constructor
            fullpath = Path(path).absolute()  # type: ignore[arg-type]

        if not fullpath.exists():
            raise OSError(f"The {fullpath} does not exist.")

        self.path = fullpath
        self._cfg = load_db_config(self.path)

        if self._cfg.backend != "postgres":
            raise ValueError(
                "AsyncKeyStore currently only supports the postgres backend. "
                "Use KeyStore for sqlite."
            )

        assert self._cfg.database_url is not None
        self._db = AsyncPgBackend.from_db_config(self._cfg)

    async def connect(self):
        """Create and return an asyncpg connection (parity with KeyStore.connect)."""
        return await self._db.connect()

    async def initialize_schema(self) -> None:
        """Initialize schema on a fresh Postgres database (parity with initialize_if_missing).

        This is idempotent (uses CREATE TABLE IF NOT EXISTS).
        For post-init version handling, see `ensure_schema_current()`.
        """
        await self._db.initialize_schema()

    async def list_fingerprints(self) -> list[str]:
        """Return all key fingerprints in the keystore DB (parity with sync KeyStore.list_fingerprints)."""
        return await self._db.list_fingerprints()

    async def save_key_info(
        self,
        *,
        keyvalue: bytes,
        fingerprint: str,
        keyid: str,
        keytype: int,
        expiration: str = "",
        creation: str = "",
        can_primary_sign: int = 0,
        oncard: str = "",
        primary_on_card: str = "",
    ) -> None:
        """Insert a minimal key row into the database (parity with sync KeyStore.save_key_info)."""
        await self._db.save_key_info(
            keyvalue=keyvalue,
            fingerprint=fingerprint,
            keyid=keyid,
            keytype=keytype,
            expiration=expiration,
            creation=creation,
            can_primary_sign=can_primary_sign,
            oncard=oncard,
            primary_on_card=primary_on_card,
        )



    async def get_key(self, fingerprint: str):
        """Return a Key by fingerprint.

        Parity target: KeyStore.get_key.
        """

        return await self._db.get_key(fingerprint)



    async def get_keys(self, qvalue: str, qtype: str = "email"):
        """Return keys by query.

        Parity target: KeyStore.get_keys.
        """

        # get_keys not implemented in AsyncPgBackend; fallback to list_fingerprints
        # or raise NotImplementedError
        raise NotImplementedError("get_keys is not implemented in AsyncPgBackend.")


    async def ensure_schema_current(self) -> None:
        """Ensure the schema exists and `dbupgrade` has the current version row."""

        await self._db.ensure_schema_current()


    async def delete_key(self, key):
        """Delete a key by fingerprint (async).

        Parity target: KeyStore.delete_key.
        """

        if isinstance(key, str):
            fingerprint = key
        elif hasattr(key, "fingerprint"):
            fingerprint = key.fingerprint
        else:
            raise TypeError(f"Wrong datatype for {str(key)}")

        await self._db.delete_key(fingerprint)

    async def update_password(self, key, password: str, newpassword: str):
        """Update password for a given key and persist updated key material (async).

        Parity target: KeyStore.update_password.
        """

        import johnnycanencrypt.johnnycanencrypt as rjce

        if not hasattr(key, "keyvalue") or not hasattr(key, "fingerprint"):
            raise TypeError("key must have 'keyvalue' and 'fingerprint' attributes")

        cert = rjce.update_password(key.keyvalue, password, newpassword)
        await self._db.update_keyvalue(fingerprint=key.fingerprint, keyvalue=cert)

        assert cert != key.keyvalue
        key.keyvalue = cert
        return key


        # NOTE: The following block references undefined 'keypath' and is unreachable; removed for clarity.




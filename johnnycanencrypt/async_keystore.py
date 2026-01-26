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

from .async_pg_backend import AsyncPgBackend
from .db import load_db_config

StrOrBytesPath = Union[str, bytes, os.PathLike]


class AsyncKeyStore:
    """Async keystore API.

    Currently supports:
    - Postgres connection acquisition via asyncpg
    - Schema initialization for a fresh database

    Configuration is environment-driven, same as KeyStore.
    """

    def __init__(self, path: StrOrBytesPath) -> None:
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
        """Create and return an asyncpg connection."""

        return await self._db.connect()

    async def initialize_schema(self) -> None:
        """Initialize schema on a fresh Postgres database.

        This is idempotent (uses CREATE TABLE IF NOT EXISTS).

        For post-init version handling, see `ensure_schema_current()`.
        """

        await self._db.initialize_schema()

    async def list_fingerprints(self) -> list[str]:
        """Return all key fingerprints in the keystore DB.

        This is the first real async DB operation (read-only) and is intended as
        a thin proof-of-life for async PostgreSQL usage.
        """

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
        """Insert a minimal key row into the database.

        This mirrors the sync KeyStore pattern where parsed cert fields are persisted.

        Notes:
        - This is intentionally minimal for now: only the `keys` table is written.
        - The full schema (subkeys/uids/certs) will be added incrementally.
        """

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

        return await self._db.get_keys(qvalue, qtype=qtype)


    async def ensure_schema_current(self) -> None:
        """Ensure the schema exists and `dbupgrade` has the current version row."""

        await self._db.ensure_schema_current()

    async def import_key(self, keypath: Union[str, Path], onplace: bool = False):
        """Import a key file into the Postgres-backed async keystore.

        Mirrors the synchronous KeyStore.import_key behavior.

        Parameters
        - keypath: path to the key file (ASCII armored or binary)
        - onplace: currently ignored (kept for API parity)
        """

        # NOTE: `parse_cert_file` returns parsed metadata, but we need the raw cert bytes
        # to store in the DB (`keys.keyvalue`).
        from .johnnycanencrypt import parse_cert_file

        if isinstance(keypath, Path):
            path = str(keypath)
        else:
            path = str(keypath)

        (
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = parse_cert_file(path)

        with open(path, "rb") as fobj:
            cert = fobj.read()

        await self._db.save_full_key(
            cert=cert,
            uids=uids,
            fingerprint=fingerprint,
            keytype=keytype,
            expirationtime=expirationtime,
            creationtime=creationtime,
            othervalues=othervalues,
        )

        return await self.get_key(fingerprint)




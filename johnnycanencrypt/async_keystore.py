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

    async def connect(self):
        """Create and return an asyncpg connection."""
        import asyncpg

        assert self._cfg.database_url is not None
        return await asyncpg.connect(self._cfg.database_url)

    async def initialize_schema(self) -> None:
        """Initialize schema on a fresh Postgres database.

        This is idempotent (uses CREATE TABLE IF NOT EXISTS).

        For post-init version handling, see `ensure_schema_current()`.
        """

        from .schema import POSTGRES_SCHEMA

        conn = await self.connect()
        try:
            await conn.execute(POSTGRES_SCHEMA)
        finally:
            await conn.close()

    async def ensure_schema_current(self) -> None:
        """Ensure the schema exists and `dbupgrade` has the current version row."""

        from .utils import DB_UPGRADE_DATE

        await self.initialize_schema()

        conn = await self.connect()
        try:
            row = await conn.fetchrow("SELECT upgradedate FROM dbupgrade LIMIT 1")
            if row is None:
                await conn.execute(
                    "INSERT INTO dbupgrade (upgradedate) VALUES ($1)", DB_UPGRADE_DATE
                )
            elif row["upgradedate"] != DB_UPGRADE_DATE:
                # Placeholder for future migrations.
                raise RuntimeError(
                    "Database schema upgrade required (dbupgrade=%r, expected=%r)"
                    % (row["upgradedate"], DB_UPGRADE_DATE)
                )
        finally:
            await conn.close()


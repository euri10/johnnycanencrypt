"""asyncpg-based PostgreSQL backend for AsyncKeyStore."""

from __future__ import annotations

from pathlib import Path

from .async_db import AsyncDbBackend
from .db import DbConfig


class AsyncPgBackend(AsyncDbBackend):
    """PostgreSQL backend implemented with asyncpg."""

    def __init__(self, *, root: Path, database_url: str) -> None:
        self.root = root
        self.database_url = database_url

    @classmethod
    def from_db_config(cls, cfg: DbConfig) -> "AsyncPgBackend":
        assert cfg.backend == "postgres"
        assert cfg.database_url is not None
        return cls(root=cfg.root, database_url=cfg.database_url)

    async def connect(self):
        import asyncpg

        return await asyncpg.connect(self.database_url)

    async def initialize_schema(self) -> None:
        from .schema import POSTGRES_SCHEMA

        conn = await self.connect()
        try:
            await conn.execute(POSTGRES_SCHEMA)
        finally:
            await conn.close()

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
                raise RuntimeError(
                    "Database schema upgrade required (dbupgrade=%r, expected=%r)"
                    % (row["upgradedate"], DB_UPGRADE_DATE)
                )
        finally:
            await conn.close()

    async def list_fingerprints(self) -> list[str]:
        await self.ensure_schema_current()

        conn = await self.connect()
        try:
            rows = await conn.fetch("SELECT fingerprint FROM keys ORDER BY fingerprint")
            return [r["fingerprint"] for r in rows]
        finally:
            await conn.close()

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
        await self.ensure_schema_current()

        conn = await self.connect()
        try:
            await conn.execute(
                """
                INSERT INTO keys (
                    keyvalue, fingerprint, keyid, keytype, expiration, creation,
                    can_primary_sign, oncard, primary_on_card
                ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                ON CONFLICT (fingerprint) DO NOTHING
                """,

                keyvalue,
                fingerprint,
                keyid,
                keytype,
                expiration,
                creation,
                can_primary_sign,
                oncard,
                primary_on_card,
            )
        finally:
            await conn.close()



    async def get_key_row_by_fingerprint(self, fingerprint: str) -> dict | None:
        """Return the raw `keys` row for a fingerprint.

        This is a building block for higher-level APIs that reconstruct the full
        Key object (uids/subkeys/certs). For now we only expose the minimal row.
        """

        await self.ensure_schema_current()

        conn = await self.connect()
        try:
            row = await conn.fetchrow(
                "SELECT * FROM keys WHERE fingerprint=$1",
                fingerprint,
            )
            return dict(row) if row is not None else None
        finally:
            await conn.close()

    async def get_key_ids_by_query(
        self, *, qvalue: str, qtype: str = "email"
    ) -> list[int]:
        """Return key IDs matching a query (email/value/name/uri).

        Mirrors the sync KeyStore.get_keys() query semantics, but returns DB ids.
        Higher-level code can then fetch full key objects.
        """

        if qtype not in ["email", "value", "uri", "name"]:
            raise ValueError("qtype must be one of: email, value, name, uri")

        await self.ensure_schema_current()

        table_by_type = {
            "value": "uidvalues",
            "email": "uidemails",
            "name": "uidnames",
            "uri": "uiduris",
        }
        table = table_by_type[qtype]

        conn = await self.connect()
        try:
            rows = await conn.fetch(
                f"SELECT DISTINCT key_id FROM {table} WHERE value=$1 ORDER BY key_id",
                qvalue,
            )
            return [int(r["key_id"]) for r in rows]
        finally:
            await conn.close()

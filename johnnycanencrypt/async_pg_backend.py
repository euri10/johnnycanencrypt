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

    async def ensure_schema_current(self) -> None:
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



    async def save_full_key(
        self,
        *,
        cert: bytes,
        uids: list[dict],
        fingerprint: str,
        keytype: bool,
        expirationtime,
        creationtime,
        othervalues: dict,
        oncard: str = "",
        primary_on_card: str = "",
    ) -> int:
        """Persist a fully parsed key into Postgres.

        Mirrors the sync KeyStore._save_key_info_to_db behavior.

        Returns
        - key_id: integer primary key in `keys`.

        Notes
        - Unlike the sync implementation, this avoids merge/update semantics for
          existing secret keys. For now it behaves like an upsert.
        """

        await self.ensure_schema_current()

        etime = str(expirationtime.timestamp()) if expirationtime else ""
        ctime = str(creationtime.timestamp()) if creationtime else ""

        ktype = 1 if keytype else 0
        subkeys = othervalues.get("subkeys") or []
        mainkeyid = othervalues.get("keyid") or ""
        can_primary_sign = othervalues.get("can_primary_sign") or 0

        conn = await self.connect()
        try:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    "SELECT id, keytype FROM keys WHERE fingerprint=$1",
                    fingerprint,
                )

                if existing:
                    key_id = int(existing["id"])
                    # For now: keep simple and update the row.
                    await conn.execute(
                        """
                        UPDATE keys
                        SET keyvalue=$1,
                            keytype=$2,
                            expiration=$3,
                            creation=$4,
                            keyid=$5,
                            can_primary_sign=$6,
                            oncard=$7,
                            primary_on_card=$8
                        WHERE id=$9
                        """,
                        cert,
                        ktype,
                        etime,
                        ctime,
                        mainkeyid,
                        can_primary_sign,
                        oncard,
                        primary_on_card,
                        key_id,
                    )
                else:
                    key_id = await conn.fetchval(
                        """
                        INSERT INTO keys (
                            keyvalue, fingerprint, keyid, keytype, expiration, creation,
                            can_primary_sign, oncard, primary_on_card
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                        RETURNING id
                        """,
                        cert,
                        fingerprint,
                        mainkeyid,
                        ktype,
                        etime,
                        ctime,
                        can_primary_sign,
                        oncard,
                        primary_on_card,
                    )
                    key_id = int(key_id)

                # Rewrite child tables (simple parity with sync behavior)
                await conn.execute("DELETE FROM subkeys WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uidcertlist WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uidcerts WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uidemails WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uidnames WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uiduris WHERE key_id=$1", key_id)
                await conn.execute("DELETE FROM uidvalues WHERE key_id=$1", key_id)

                # subkeys: tuples like (keyid, fingerprint, creation_dt, expiration_dt, keytype, revoked)
                for subkey in subkeys:
                    sk_ctime = str(subkey[2].timestamp()) if subkey[2] else ""
                    sk_etime = str(subkey[3].timestamp()) if subkey[3] else ""
                    await conn.execute(
                        """
                        INSERT INTO subkeys (
                            key_id, fingerprint, keyid, expiration, creation, keytype, revoked
                        ) VALUES ($1,$2,$3,$4,$5,$6,$7)
                        """,
                        key_id,
                        subkey[1],
                        subkey[0],
                        sk_etime,
                        sk_ctime,
                        subkey[4],
                        int(bool(subkey[5])),
                    )

                for uid in uids:
                    if not uid.get("value"):
                        continue

                    revoked = 1 if uid.get("revoked") else 0
                    value_id = await conn.fetchval(
                        """
                        INSERT INTO uidvalues (value, revoked, key_id)
                        VALUES ($1,$2,$3)
                        RETURNING id
                        """,
                        uid["value"],
                        revoked,
                        key_id,
                    )
                    value_id = int(value_id)

                    # certifications
                    certs = uid.get("certifications") or []
                    for ucert in certs:
                        ucert_ctime = ucert.get("creationtime")
                        ucert_ctime_str = (
                            str(ucert_ctime.timestamp()) if ucert_ctime else ""
                        )
                        ucert_id = await conn.fetchval(
                            """
                            INSERT INTO uidcerts (ctype, creation, key_id, value_id)
                            VALUES ($1,$2,$3,$4)
                            RETURNING id
                            """,
                            ucert.get("certification_type") or "",
                            ucert_ctime_str,
                            key_id,
                            value_id,
                        )
                        ucert_id = int(ucert_id)

                        for datatype, value in (ucert.get("certification_list") or []):
                            await conn.execute(
                                """
                                INSERT INTO uidcertlist (value, datatype, key_id, value_id, cert_id)
                                VALUES ($1,$2,$3,$4,$5)
                                """,
                                value,
                                datatype,
                                key_id,
                                value_id,
                                ucert_id,
                            )

                    # uid emails/names/uris
                    if uid.get("email"):
                        await conn.execute(
                            "INSERT INTO uidemails (value, key_id, value_id) VALUES ($1,$2,$3)",
                            uid["email"],
                            key_id,
                            value_id,
                        )
                    if uid.get("name"):
                        await conn.execute(
                            "INSERT INTO uidnames (value, key_id, value_id) VALUES ($1,$2,$3)",
                            uid["name"],
                            key_id,
                            value_id,
                        )
                    if uid.get("uri"):
                        await conn.execute(
                            "INSERT INTO uiduris (value, key_id, value_id) VALUES ($1,$2,$3)",
                            uid["uri"],
                            key_id,
                            value_id,
                        )

                return key_id
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


"""Database backend abstraction used by KeyStore.

This module is intentionally small and focused:
- Define a backend protocol (shape) for the DB operations KeyStore needs.
- Provide the current SQLite implementation behind that protocol.

PostgreSQL support will add a second implementation without changing KeyStore call sites.
"""

from __future__ import annotations

import os

from dataclasses import dataclass

from pathlib import Path
from typing import Literal, Protocol, Optional




@dataclass(frozen=True)
class DbConfig:
    """Configuration for the keystore database (parity with AsyncDbConfig).

    `KeyStore` is directory-based, but the database backend can be selected.

    Environment-driven selection (initial implementation):
    - `JCE_DB_BACKEND`: "sqlite" (default) or "postgres"
    - `JCE_DATABASE_URL`: connection URL/DSN (required for postgres)

    For sqlite, `root` is used and the DB lives at `<root>/jce.db`.
    """

    root: Path
    backend: Literal["sqlite", "postgres"] = "sqlite"
    database_url: Optional[str] = None


def load_db_config(root: Path) -> DbConfig:
    """Load DB config from environment.

    Defaults preserve existing behavior (sqlite file under `root`).

    Supported variables:
    - `JCE_DB_BACKEND`: sqlite | postgres | postgresql (default: sqlite)
    - `JCE_DATABASE_URL`: preferred DSN/URL for postgres
    - `DATABASE_URL`: fallback DSN/URL for postgres (common convention)
    """

    backend_raw = (os.getenv("JCE_DB_BACKEND") or "sqlite").strip().lower()
    backend_aliases = {
        "sqlite": "sqlite",
        "postgres": "postgres",
        "postgresql": "postgres",
    }
    backend = backend_aliases.get(backend_raw)
    if backend is None:
        raise ValueError(
            "Invalid JCE_DB_BACKEND. Expected 'sqlite', 'postgres', or 'postgresql', got: %r"
            % backend_raw
        )

    database_url = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")

    if backend == "postgres" and not database_url:
        raise ValueError(
            "JCE_DATABASE_URL (or DATABASE_URL) is required when JCE_DB_BACKEND is postgres"
        )

    return DbConfig(
        root=root,
        backend=backend,
        database_url=database_url,
    )




class DbBackend(Protocol):
    """DB backend contract required by KeyStore (parity with AsyncDbBackend).

    This is deliberately minimal and mirrors how KeyStore uses sqlite3 today.
    """

    def connect(self):
        """Return a DB-API compatible connection (context-manageable, parity with AsyncDbBackend.connect)."""

    def initialize_if_missing(self) -> None:
        """Create schema and write dbupgrade row if DB doesn't exist yet (parity with AsyncDbBackend.initialize_schema)."""

    def upgrade_if_required(self) -> None:
        """Migrate/upgrade schema if the existing DB is older than current (parity with AsyncDbBackend.ensure_schema_current)."""



class SqliteBackend:
    """SQLite implementation of DbBackend.

    This keeps all sqlite3-specific behavior isolated from KeyStore.

    NOTE: This backend currently assumes a *directory-based* keystore layout where the
    SQLite DB file lives at `<keystore_dir>/jce.db`.
    """


    def __init__(self, cfg: DbConfig, *, db_filename: str = "jce.db") -> None:
        import sqlite3

        self._sqlite3 = sqlite3
        self.cfg = cfg
        self.dbpath = cfg.root / db_filename

    def connect(self):
        con = self._sqlite3.connect(self.dbpath)
        con.row_factory = self._sqlite3.Row
        return con

    def initialize_if_missing(self) -> None:
        from ..utils import DB_UPGRADE_DATE, createdb

        if self.dbpath.exists():
            return

        con = self._sqlite3.connect(self.dbpath)
        with con:
            cursor = con.cursor()
            cursor.executescript(createdb)
            cursor.execute(
                "INSERT INTO dbupgrade (upgradedate) values (?)",
                (DB_UPGRADE_DATE,),
            )

    def upgrade_if_required(self) -> None:
        """Upgrade the SQLite database schema in-place if required.

        Use `upgrade_if_required_with(...)` for now.

        This method intentionally raises to avoid silently doing nothing.
        """

        raise RuntimeError(
            "SqliteBackend.upgrade_if_required() requires callbacks; "
            "call upgrade_if_required_with(...)"
        )


    def upgrade_if_required_with(
        self,
        *,
        save_key_info_to_db,
        parse_cert_bytes,
        db_upgrade_date: str,
        createdb_sql: str,
    ) -> None:
        """Backend-specific upgrade that depends on KeyStore's insert logic.

        Parameters
        - save_key_info_to_db: callable matching KeyStore._save_key_info_to_db
        - parse_cert_bytes: callable matching johnnycanencrypt.parse_cert_bytes
        - db_upgrade_date: schema version string
        - createdb_sql: SQL script to initialize schema
        """

        SHOULD_WE = False
        existing_records = []

        con = self.connect()
        with con:
            cursor = con.cursor()
            try:
                cursor.execute("SELECT * from dbupgrade")
                fromdb = cursor.fetchone()
                if fromdb["upgradedate"] < db_upgrade_date:
                    SHOULD_WE = True
            except self._sqlite3.OperationalError:
                SHOULD_WE = True

            if SHOULD_WE:
                cursor.execute("SELECT * from KEYS")
                existing_records = cursor.fetchall()
            else:
                return

        # Temporay db setup
        oldpath = self.dbpath
        upgrade_path = self.cfg.root / "jce_upgrade.db"
        if upgrade_path.exists():
            raise RuntimeError(
                f"{upgrade_path} already exists, please remove and then try again."
            )

        # Create new DB at upgrade_path
        self.dbpath = upgrade_path


        con = self.connect()
        with con:
            cursor = con.cursor()
            cursor.executescript(createdb_sql)
            cursor.execute(
                "INSERT INTO dbupgrade (upgradedate) values (?)",
                (db_upgrade_date,),
            )

        # Copy existing data
        for row in existing_records:
            (
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            ) = parse_cert_bytes(row["keyvalue"])
            save_key_info_to_db(
                row["keyvalue"],
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            )

        # Restore oncard fields (may not exist in old schema)
        con = self.connect()
        with con:
            cursor = con.cursor()
            for row in existing_records:
                oncard = row["oncard"]
                try:
                    primary_on_card = row["primary_on_card"]
                except IndexError:
                    primary_on_card = ""
                fingerprint = row["fingerprint"]
                cursor.execute(
                    "UPDATE keys set oncard=?, primary_on_card=? where fingerprint=?",
                    (oncard, primary_on_card, fingerprint),
                )

        # Swap upgraded DB into place
        import os
        import shutil

        os.unlink(oldpath)
        shutil.copy(self.dbpath, oldpath)
        os.unlink(self.dbpath)

        self.dbpath = oldpath

        # Ensure backend returned to the stable path (defensive).
        assert self.dbpath == oldpath




import os
from typing import Any
from pathlib import Path
import pytest
from johnnycanencrypt.async_db.pg_backend import AsyncPgBackend


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")

# ...existing code...

@pytest.mark.anyio
async def test_async_pg_backend_ensure_schema_current(tmp_path: Path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)
    await backend.ensure_schema_current()


@pytest.mark.anyio
async def test_async_pg_backend_list_fingerprints_empty(tmp_path: Path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)
    fps = await backend.list_fingerprints()
    assert fps == []


@pytest.mark.anyio
async def test_async_pg_backend_save_key_info_roundtrip(tmp_path: Path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)

    await backend.save_key_info(
        keyvalue=b"dummy",
        fingerprint="ABCDEF",
        keyid="ABCDEF",
        keytype=0,
        expiration="",
        creation="",
        can_primary_sign=0,
        oncard="",
        primary_on_card="",
    )

    fps = await backend.list_fingerprints()
    assert fps == ["ABCDEF"]

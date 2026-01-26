import os

import pytest


def test_async_keystore_requires_postgres_backend(tmp_path, monkeypatch):
    monkeypatch.delenv("JCE_DB_BACKEND", raising=False)
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    monkeypatch.setenv("JCE_DB_BACKEND", "sqlite")

    from johnnycanencrypt.async_keystore import AsyncKeyStore

    with pytest.raises(ValueError, match=r"only supports the postgres backend"):
        AsyncKeyStore(tmp_path)


@pytest.mark.anyio
async def test_async_keystore_can_init_schema_with_postgres(tmp_path, monkeypatch):
    """Integration test (optional).

    Runs only when a real Postgres DSN is available.
    """

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from johnnycanencrypt.async_keystore import AsyncKeyStore
    from johnnycanencrypt.utils import DB_UPGRADE_DATE

    ks = AsyncKeyStore(tmp_path)
    await ks.ensure_schema_current()

    conn = await ks.connect()
    try:
        row = await conn.fetchrow("SELECT upgradedate FROM dbupgrade LIMIT 1")
        assert row is not None
        assert row["upgradedate"] == DB_UPGRADE_DATE
    finally:
        await conn.close()


@pytest.mark.anyio
async def test_async_keystore_list_fingerprints_smoke(tmp_path, monkeypatch):
    """Optional integration smoke test.

    Requires a Postgres DSN. Validates that list_fingerprints works on an empty DB.
    """

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)
    fps = await ks.list_fingerprints()
    assert fps == []


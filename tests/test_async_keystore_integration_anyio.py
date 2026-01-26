import os

import pytest


@pytest.mark.anyio
async def test_async_keystore_integration_tests_run_with_dsn(tmp_path, monkeypatch):
    """Sanity check: when DSN is available, async tests can run (not just skip)."""

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)
    await ks.ensure_schema_current()


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

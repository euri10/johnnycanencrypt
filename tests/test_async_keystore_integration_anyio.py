import os
from typing import Any
from pathlib import Path
import pytest
from johnnycanencrypt.async_db.keystore import AsyncKeyStore

# ...existing code...

@pytest.mark.anyio
async def test_async_keystore_integration_tests_run_with_dsn(tmp_path: Path, monkeypatch: Any):
    """Sanity check: when DSN is available, async tests can run (not just skip)."""

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    ks = AsyncKeyStore(tmp_path)
    await ks.ensure_schema_current()


@pytest.mark.anyio
async def test_async_keystore_list_fingerprints_smoke(tmp_path: Path, monkeypatch: Any):
    """Optional integration smoke test.

    Requires a Postgres DSN. Validates that list_fingerprints works on an empty DB.
    """

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    ks = AsyncKeyStore(tmp_path)
    fps = await ks.list_fingerprints()
    assert fps == []


@pytest.mark.anyio
async def test_async_keystore_save_key_info_roundtrip(tmp_path: Path, monkeypatch: Any):
    """Integration test for the first async write operation."""

    dsn = os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    ks = AsyncKeyStore(tmp_path)

    await ks.save_key_info(
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

    fps = await ks.list_fingerprints()
    assert fps == ["ABCDEF"]


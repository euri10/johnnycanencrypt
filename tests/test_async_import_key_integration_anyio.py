import os

import pytest


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")


@pytest.mark.anyio
async def test_async_keystore_import_key_roundtrip(tmp_path, monkeypatch):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from conftest import BASE_TESTSDIR
    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)

    key = await ks.import_key(BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc")

    # Fingerprint is asserted by follow-up get_key call
    key2 = await ks.get_key(key.fingerprint)
    assert key2.fingerprint == key.fingerprint

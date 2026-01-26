import os

import pytest


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")


@pytest.mark.anyio
async def test_async_keystore_delete_key_cleans_up(tmp_path, monkeypatch):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from conftest import BASE_TESTSDIR
    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)

    # Import a key with subkeys/uids so we can validate cleanup.
    key = await ks.import_key(BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc")

    # Ensure it exists
    _ = await ks.get_key(key.fingerprint)

    await ks.delete_key(key.fingerprint)

    # Now verify it no longer exists
    import johnnycanencrypt as jce

    with pytest.raises(jce.KeyNotFoundError):
        await ks.get_key(key.fingerprint)


@pytest.mark.anyio
async def test_async_keystore_update_password_smoke(tmp_path, monkeypatch):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from conftest import BASE_TESTSDIR
    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)

    # secret.asc is used by sync tests for update_password
    key = await ks.import_key(BASE_TESTSDIR / "files" / "store" / "secret.asc")

    # This should update DB keyvalue bytes
    key2 = await ks.update_password(key, "redhat", "byebye")
    assert key2.fingerprint == key.fingerprint

    # Re-load and ensure keyvalue changed
    key3 = await ks.get_key(key.fingerprint)
    assert key3.keyvalue == key2.keyvalue

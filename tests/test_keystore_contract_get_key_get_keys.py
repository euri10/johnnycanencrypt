"""Contract tests for keystore read APIs.

Goal: ensure the same expectations hold for:
- sync KeyStore (SQLite)
- async AsyncKeyStore (Postgres via asyncpg)

These tests intentionally exercise only the read-path APIs:
- get_key(fingerprint)
- get_keys(qvalue, qtype)

They use existing fixture keys (pgp_keys.asc) to avoid duplicating parsing logic.
"""

from __future__ import annotations

import os

import pytest


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")


def _import_fixture_sync(tmp_path):
    from conftest import BASE_TESTSDIR
    import johnnycanencrypt as jce

    ks = jce.KeyStore(tmp_path)
    key = ks.import_key(BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc")
    return ks, key


async def _import_fixture_async(tmp_path, monkeypatch):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.setenv("JCE_DATABASE_URL", dsn)

    from conftest import BASE_TESTSDIR
    from johnnycanencrypt.async_keystore import AsyncKeyStore

    ks = AsyncKeyStore(tmp_path)
    key = await ks.import_key(BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc")
    return ks, key


def _assert_key_parity_basics(key):
    assert key.fingerprint
    assert key.keyid
    # Should have at least one UID and structured fields
    assert len(key.uids) > 0
    assert any(u.get("email") for u in key.uids)
    assert any(u.get("name") for u in key.uids)


def test_contract_sync_get_key_and_get_keys(tmp_path):
    ks, imported_key = _import_fixture_sync(tmp_path)

    key2 = ks.get_key(imported_key.fingerprint)
    assert key2.fingerprint == imported_key.fingerprint
    _assert_key_parity_basics(key2)

    # email search
    email = next(u["email"] for u in key2.uids if u.get("email"))
    found = ks.get_keys(qvalue=email, qtype="email")
    assert any(k.fingerprint == key2.fingerprint for k in found)


@pytest.mark.anyio
async def test_contract_async_get_key_and_get_keys(tmp_path, monkeypatch):
    ks, imported_key = await _import_fixture_async(tmp_path, monkeypatch)

    key2 = await ks.get_key(imported_key.fingerprint)
    assert key2.fingerprint == imported_key.fingerprint
    _assert_key_parity_basics(key2)

    email = next(u["email"] for u in key2.uids if u.get("email"))
    found = await ks.get_keys(qvalue=email, qtype="email")
    assert any(k.fingerprint == key2.fingerprint for k in found)

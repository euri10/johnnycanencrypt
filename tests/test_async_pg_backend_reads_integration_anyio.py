import os

import pytest


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")


@pytest.mark.anyio
async def test_async_pg_backend_get_key_row_by_fingerprint(tmp_path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    from johnnycanencrypt.async_pg_backend import AsyncPgBackend

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)

    await backend.save_key_info(
        keyvalue=b"dummy",
        fingerprint="ABCDEF",
        keyid="ABCDEF",
        keytype=0,
    )

    row = await backend.get_key_row_by_fingerprint("ABCDEF")
    assert row is not None
    assert row["fingerprint"] == "ABCDEF"


@pytest.mark.anyio
async def test_async_pg_backend_get_key_ids_by_query_email(tmp_path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    from johnnycanencrypt.async_pg_backend import AsyncPgBackend

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)

    # Insert a key
    await backend.save_key_info(
        keyvalue=b"dummy",
        fingerprint="ABCDEF",
        keyid="ABCDEF",
        keytype=0,
    )

    # Insert an email uid row pointing at that key id
    conn = await backend.connect()
    try:
        kid = await conn.fetchval("SELECT id FROM keys WHERE fingerprint=$1", "ABCDEF")
        assert kid is not None
        await conn.execute(
            "INSERT INTO uidvalues (value, revoked, key_id) VALUES ($1,$2,$3)",
            "User <user@example.com>",
            0,
            kid,
        )
        vid = await conn.fetchval(
            "SELECT id FROM uidvalues WHERE key_id=$1 AND value=$2",
            kid,
            "User <user@example.com>",
        )
        assert vid is not None
        await conn.execute(
            "INSERT INTO uidemails (value, key_id, value_id) VALUES ($1,$2,$3)",
            "user@example.com",
            kid,
            vid,
        )
    finally:
        await conn.close()

    ids = await backend.get_key_ids_by_query(qvalue="user@example.com", qtype="email")
    assert ids == [kid]

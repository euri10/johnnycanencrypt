import os

import pytest


def _get_dsn() -> str | None:
    return os.getenv("JCE_DATABASE_URL") or os.getenv("DATABASE_URL")


@pytest.mark.anyio
async def test_async_pg_backend_schema_mismatch_raises_clear_error(tmp_path):
    dsn = _get_dsn()
    if not dsn:
        pytest.skip("Missing JCE_DATABASE_URL/DATABASE_URL for Postgres integration test")

    from johnnycanencrypt.async_pg_backend import AsyncPgBackend
    from johnnycanencrypt.utils import DB_UPGRADE_DATE

    backend = AsyncPgBackend(root=tmp_path, database_url=dsn)

    # Ensure schema exists, then force an old version.
    await backend.ensure_schema_current()

    conn = await backend.connect()
    try:
        await conn.execute("DELETE FROM dbupgrade")
        await conn.execute("INSERT INTO dbupgrade (upgradedate) VALUES ($1)", "19000101")
    finally:
        await conn.close()

    with pytest.raises(RuntimeError) as exc:
        await backend.ensure_schema_current()

    msg = str(exc.value)
    assert "Automatic Postgres migrations are not implemented" in msg
    assert DB_UPGRADE_DATE in msg

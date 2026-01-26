
import pytest


def test_async_keystore_requires_postgres_backend(tmp_path, monkeypatch):
    monkeypatch.delenv("JCE_DB_BACKEND", raising=False)
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    monkeypatch.setenv("JCE_DB_BACKEND", "sqlite")

    from johnnycanencrypt.async_keystore import AsyncKeyStore

    with pytest.raises(ValueError, match=r"only supports the postgres backend"):
        AsyncKeyStore(tmp_path)





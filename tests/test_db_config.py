
import pytest
import johnnycanencrypt.db as jcedb


def test_db_config_default_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("JCE_DB_BACKEND", raising=False)
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)

    cfg = jcedb.load_db_config(tmp_path)
    assert cfg.backend == "sqlite"
    assert cfg.database_url is None


def test_db_config_invalid_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("JCE_DB_BACKEND", "nope")
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match=r"Invalid JCE_DB_BACKEND"):
        jcedb.load_db_config(tmp_path)


def test_db_config_postgres_requires_url(tmp_path, monkeypatch):
    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(ValueError, match=r"JCE_DATABASE_URL \(or DATABASE_URL\) is required"):
        jcedb.load_db_config(tmp_path)


def test_db_config_postgresql_alias(tmp_path, monkeypatch):
    monkeypatch.setenv("JCE_DB_BACKEND", "postgresql")
    monkeypatch.setenv("JCE_DATABASE_URL", "postgresql://localhost/db")

    cfg = jcedb.load_db_config(tmp_path)
    assert cfg.backend == "postgres"


def test_db_config_database_url_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("JCE_DB_BACKEND", "postgres")
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")

    cfg = jcedb.load_db_config(tmp_path)
    assert cfg.database_url == "postgresql://localhost/db"


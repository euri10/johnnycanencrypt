
from typing import Any
from pathlib import Path
import pytest
from johnnycanencrypt.async_db.keystore import AsyncKeyStore

# ...existing code...

def test_async_keystore_requires_postgres_backend(tmp_path: Path, monkeypatch: Any):
    monkeypatch.delenv("JCE_DB_BACKEND", raising=False)
    monkeypatch.delenv("JCE_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    monkeypatch.setenv("JCE_DB_BACKEND", "sqlite")

    # ...existing code...

    with pytest.raises(ValueError, match=r"only supports the postgres backend"):
        AsyncKeyStore(tmp_path)





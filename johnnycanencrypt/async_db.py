"""Async database backend abstraction for AsyncKeyStore.

This mirrors the synchronous backend abstraction in `johnnycanencrypt.db`, but is
explicitly async-first to support asyncpg without forcing synchronous callers
into event loop management.

Initial implementation provides an asyncpg-based PostgreSQL backend.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional, Protocol


@dataclass(frozen=True)
class AsyncDbConfig:
    """Configuration for the async keystore database."""

    root: Path
    backend: Literal["postgres"] = "postgres"
    database_url: Optional[str] = None


class AsyncDbBackend(Protocol):
    """Async DB backend contract required by AsyncKeyStore."""

    async def connect(self):
        """Return an open async connection."""

    async def initialize_schema(self) -> None:
        """Create schema on a fresh database (idempotent)."""

    async def ensure_schema_current(self) -> None:
        """Ensure schema exists and is at the expected version."""

    async def list_fingerprints(self) -> list[str]:
        """Return all key fingerprints."""

    async def save_key_info(
        self,
        *,
        keyvalue: bytes,
        fingerprint: str,
        keyid: str,
        keytype: int,
        expiration: str = "",
        creation: str = "",
        can_primary_sign: int = 0,
        oncard: str = "",
        primary_on_card: str = "",
    ) -> None:
        """Persist a minimal key row."""

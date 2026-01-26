"""Database schema definitions.

Right now the keystore schema is defined as raw SQL for SQLite.
PostgreSQL support will reuse the same logical schema with Postgres-friendly DDL.

These SQL strings are intended to be executed on a fresh database.
"""

# SQLite schema (kept for reference / parity checks)
from .utils import createdb as SQLITE_SCHEMA


POSTGRES_SCHEMA = """
-- Keystore schema for PostgreSQL

CREATE TABLE IF NOT EXISTS keys (
    id BIGSERIAL PRIMARY KEY,
    keyvalue BYTEA NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,

    keyid TEXT NOT NULL,
    expiration TEXT,
    creation TEXT,
    keytype INTEGER,
    can_primary_sign INTEGER,
    oncard TEXT,
    primary_on_card TEXT
);

CREATE TABLE IF NOT EXISTS subkeys (
    id BIGSERIAL PRIMARY KEY,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    keyid TEXT NOT NULL,
    expiration TEXT,
    creation TEXT,
    keytype TEXT,
    revoked INTEGER
);

CREATE TABLE IF NOT EXISTS uidvalues (
    id BIGSERIAL PRIMARY KEY,
    value TEXT,
    revoked INTEGER,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uidcerts (
    id BIGSERIAL PRIMARY KEY,
    ctype TEXT NOT NULL,
    creation TEXT,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    value_id BIGINT REFERENCES uidvalues (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uidcertlist (
    id BIGSERIAL PRIMARY KEY,
    value TEXT,
    datatype TEXT,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    value_id BIGINT REFERENCES uidvalues (id) ON DELETE CASCADE,
    cert_id BIGINT REFERENCES uidcerts (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uidemails (
    id BIGSERIAL PRIMARY KEY,
    value TEXT,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    value_id BIGINT REFERENCES uidvalues (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uidnames (
    id BIGSERIAL PRIMARY KEY,
    value TEXT,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    value_id BIGINT REFERENCES uidvalues (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS uiduris (
    id BIGSERIAL PRIMARY KEY,
    value TEXT,
    key_id BIGINT REFERENCES keys (id) ON DELETE CASCADE,
    value_id BIGINT REFERENCES uidvalues (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dbupgrade (
    upgradedate TEXT
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_keys_fingerprint ON keys (fingerprint);
CREATE INDEX IF NOT EXISTS idx_keys_keyid ON keys (keyid);
CREATE INDEX IF NOT EXISTS idx_subkeys_key_id ON subkeys (key_id);
CREATE INDEX IF NOT EXISTS idx_subkeys_fingerprint ON subkeys (fingerprint);
CREATE INDEX IF NOT EXISTS idx_uidvalues_key_id ON uidvalues (key_id);
CREATE INDEX IF NOT EXISTS idx_uidemails_value ON uidemails (value);
CREATE INDEX IF NOT EXISTS idx_uidnames_value ON uidnames (value);
CREATE INDEX IF NOT EXISTS idx_uiduris_value ON uiduris (value);
"""

import re

import johnnycanencrypt.schema as schema


def test_postgres_schema_has_all_tables():
    # very light smoke test: verify all key tables are present as CREATE TABLE statements
    ddl = schema.POSTGRES_SCHEMA.lower()
    for table in [
        "keys",
        "subkeys",
        "uidvalues",
        "uidcerts",
        "uidcertlist",
        "uidemails",
        "uidnames",
        "uiduris",
        "dbupgrade",
    ]:
        assert f"create table if not exists {table}" in ddl


def test_postgres_schema_uses_bytea_for_keyvalue():
    ddl = schema.POSTGRES_SCHEMA.lower()
    assert re.search(r"keyvalue\s+bytea\s+not\s+null", ddl)

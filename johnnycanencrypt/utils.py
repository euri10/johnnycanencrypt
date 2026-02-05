import datetime

createdb = """
CREATE TABLE keys (
	id INTEGER PRIMARY KEY,
	keyvalue BLOB NOT NULL,
	fingerprint TEXT NOT NULL,
	keyid TEXT NOT NULL,
	expiration TEXT,
	creation TEXT,
	keytype INTEGER,
    can_primary_sign INTEGER,
    oncard TEXT,
    primary_on_card TEXT
);

CREATE TABLE subkeys (
	id INTEGER PRIMARY KEY,
	key_id INTEGER,
	fingerprint TEXT NOT NULL,
	keyid TEXT NOT NULL,
	expiration TEXT,
	creation TEXT,
	keytype TEXT,
	revoked INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
);

CREATE TABLE uidvalues (
	id INTEGER PRIMARY KEY,
	value TEXT,
	revoked INTEGER,
	key_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
);

CREATE TABLE uidcerts (
	id INTEGER PRIMARY KEY,
	ctype TEXT NOT NULL,
	creation TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE uidcertlist (
	id INTEGER PRIMARY KEY,
	value TEXT,
	datatype TEXT,
	key_id INTEGER,
	value_id INTEGER,
	cert_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
	FOREIGN KEY (cert_id)
	REFERENCES uidcerts (id)
		ON DELETE CASCADE
);

CREATE TABLE uidemails (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE uidnames (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE uiduris (
	id INTEGER PRIMARY KEY,
	value TEXT,
	key_id INTEGER,
	value_id INTEGER,
	FOREIGN KEY (key_id)
	REFERENCES keys (id)
		ON DELETE CASCADE
	FOREIGN KEY (value_id)
	REFERENCES uidvalues (id)
		ON DELETE CASCADE
);

CREATE TABLE dbupgrade (upgradedate TEXT)
"""

DB_UPGRADE_DATE = "20250213"


def convert_fingerprint(data: str) -> str:
    "Converts binary data to fingerprint string"
    s = ""
    for x in data:
        s += format(x, "02x")
    return s.upper()


def to_sort_by_expiry(date: dict[str, datetime.datetime | None]) -> datetime.datetime:
    "To help to sort based on expiration date"
    if date["expiration"] is not None:
        return date["expiration"]
    return datetime.datetime(2050, 3, 24, 23, 49, 1)


# keys
UPDATE_PASSWORD_SQL = (
    "update keys set keyvalue=:keyvalue where fingerprint=:fingerprint"
)

SELECT_KEY_BY_FINGERPRINT_SQL = "select * from keys where fingerprint=:fingerprint"

SELECT_KEY_BY_KEYID_SQL = "SELECT * FROM keys WHERE keyid=:keyid"

SELECT_KEY_BY_ID_SQL = "SELECT * FROM keys WHERE id=:keyid"

SELECT_KEYID_SQL = "SELECT id from keys where fingerprint=:fingerprint"

SELECT_ALL_KEYS = "SELECT * FROM keys"

# subkeys
SELECT_SUBKEY_BY_KEYID = "SELECT * FROM subkeys WHERE keyid=:keyid"

SELECT_ALLSUBKEYS_BY_KEY_ID = "SELECT * FROM subkeys WHERE key_id=:key_id"

# uidvalues
SELECT_UIDVALUES_SQL = "SELECT id FROM uidvalues WHERE key_id=(SELECT id FROM keys where fingerprint=:fingerprint) AND value=:value"

SELECT_UIDVALUES_BY_KEYID = (
    "SELECT id, value, revoked FROM uidvalues WHERE key_id=:key_id"
)

SELECT_UIDVALUES_BY_VALUE = "SELECT id, key_id FROM uidvalues where value=:value"
# other uid tables
SELECT_UIDEMAILS_BY_VALUE = "SELECT id, key_id FROM uidemails where value=:value"

SELECT_UIDNAMES_BY_VALUE = "SELECT id, key_id FROM uidenames where value=:value"

SELECT_UIDURIS_BY_VALUE = "SELECT id, key_id FROM uiduris where value=:value"

# details count
SELECT_PUB_PRIV_COUNT_SQL = """
            SELECT
                SUM(CASE WHEN keytype = 0 THEN 1 ELSE 0 END) AS public,
                SUM(CASE WHEN keytype = 1 THEN 1 ELSE 0 END) AS secret
            FROM keys
            """

SELECT_UIDCERTLIST_BY_CERTID = (
    "SELECT value, datatype FROM uidcertlist WHERE cert_id=:cert_id"
)

SELECT_UIDCERT_BY_KEYID = "SELECT id, ctype, creation FROM uidcerts WHERE key_id=:key_id and value_id=:value_id"

UPDATE_KEY_SQL = "UPDATE keys SET keyvalue=:keyvalue, keytype=:keytype, expiration=:expiration, creation=:creation WHERE id=:id"

UPDATE_SUBKEY_EXPIRATION_SQL = (
    "UPDATE subkeys set expiration=:expiration where fingerprint=:fingerprint"
)

UPDATE_KEY_EXPIRATION_SQL = (
    "UPDATE keys set expiration=:expiration where fingerprint=:fingerprint"
)

UPDATE_REVOKED_SQL = (
    "UPDATE uidvalues set revoked=:revoked where id=:key_id returning *"
)

INSERT_KEY_SQL = "INSERT INTO keys (keyvalue, fingerprint, keyid, keytype, expiration, creation, can_primary_sign) VALUES(:keyvalue, :fingerprint, :keyid, :keytype, :expiration, :creation, :can_primary_sign) RETURNING id"

INSERT_SUBKEYS_SQL = "INSERT INTO subkeys (key_id, fingerprint, keyid, expiration, creation, keytype, revoked) VALUES(:key_id, :fingerprint, :keyid, :expiration, :creation, :keytype, :revoked)"

INSERT_UIDVALUES_SQL = "INSERT INTO uidvalues (value, revoked, key_id) values (:value, :revoked, :key_id) returning id"

INSERT_UIDCERTS_SQL = "INSERT INTO uidcerts (ctype, creation, key_id, value_id) values (:ctype, :creation, :key_id, :value_id) returning *"

INSERT_UIDCERTLIST_SQL = "INSERT INTO uidcertlist (value, datatype, key_id, value_id, cert_id) values (:value, :datatype, :key_id, :value_id, :cert_id)"

DELETE_X_SQL = "DELETE FROM :tablename WHERE id=:key_id"


DELETE_KEY_BY_FINGERPRINT = "DELETE FROM keys where fingerprint=:fingerprint"
DELETE_SUBBEYS_BY_KEY_ID = "DELETE FROM subkeys where key_id=:key_id"

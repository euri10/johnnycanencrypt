-- SQLSpec Migration
-- Version: 0001
-- Description: initial migrations for jce
-- Created: 2026-02-01T09:00:03.154718+00:00
-- Author: euri10 <benoit.barthelet@gmail.com>

-- name: migrate-0001-up
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

CREATE TABLE dbupgrade (upgradedate TEXT);


-- name: migrate-0001-down

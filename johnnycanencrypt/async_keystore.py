# pyright: reportAny=false

from dataclasses import dataclass
import logging
import os
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Self, override
from urllib.parse import quote

import httpx
from sqlspec import SQLResult, SQLSpec, AsyncDatabaseConfig
from sqlspec.exceptions import SQLSpecError

from johnnycanencrypt.exceptions import FetchingError, KeyNotFoundError
from johnnycanencrypt.key import Cipher, Key, KeyType, SignatureType, StrOrBytesPath
from johnnycanencrypt.utils import (
    INSERT_KEY_SQL,
    INSERT_SUBKEYS_SQL,
    INSERT_UIDCERTLIST_SQL,
    INSERT_UIDCERTS_SQL,
    INSERT_UIDVALUES_SQL,
    SELECT_ALL_KEYS,
    SELECT_KEY_BY_FINGERPRINT_SQL,
    SELECT_KEY_BY_ID_SQL,
    SELECT_KEY_BY_KEYID_SQL,
    SELECT_KEYID_SQL,
    SELECT_PUB_PRIV_COUNT_SQL,
    SELECT_SUBKEY_BY_KEYID,
    SELECT_UIDVALUES_SQL,
    UPDATE_KEY_EXPIRATION_SQL,
    UPDATE_KEY_SQL,
    UPDATE_PASSWORD_SQL,
    UPDATE_REVOKED_SQL,
    UPDATE_SUBKEY_EXPIRATION_SQL,
    convert_fingerprint,
    to_sort_by_expiry,
)

from .johnnycanencrypt import (
    CryptoError,
    Johnny,
    SameKeyError,
    add_uid_in_cert,
    certify_key,
    create_key,
    decrypt_bytes_on_card,
    decrypt_file_on_card,
    decrypt_filehandler_on_card,
    encrypt_bytes_to_bytes,
    encrypt_bytes_to_file,
    encrypt_file_internal,
    encrypt_filehandler_to_file,
    get_card_details,
    merge_keys,
    parse_cert_bytes,
    parse_cert_file,
    revoke_uid_in_cert,
    sign_bytes_detached_on_card,
    sign_file_detached_on_card,
    sign_file_on_card,
    update_password,
    update_primary_expiry_in_cert,
    update_subkeys_expiry_in_cert,
)

logger = logging.getLogger(__name__)


class AsyncKeyStore:
    """Returns `KeyStore` class object, takes the directory path as string."""

    def __init__(
        self,
        spec: SQLSpec,
        config: AsyncDatabaseConfig[Any, Any, Any],
        path: Path,
    ) -> None:
        self.spec = spec
        migration_config = {
            "script_location": "/home/lotso/code/johnnycanencrypt/johnnycanencrypt/jce_migrations/"
        }
        config.migration_config = migration_config
        config._initialize_migration_components()
        self.config = config
        self.path = path

    @classmethod
    async def create(
        cls,
        spec: SQLSpec,
        config: AsyncDatabaseConfig[
            Any,
            Any,
            Any,
        ],
        path: Path,
    ) -> Self:
        self = cls(spec=spec, config=config, path=path)
        current = await config.get_current_migration()
        if not current:
            try:
                await config.migrate_up(echo=True)
            except Exception as e:
                raise e
        return self

    @override
    def __str__(self) -> str:
        return f"<KeyStore dbpath={self.config.connection_config}>"

    async def update_password(self, key: Key, password: str, newpassword: str) -> Key:
        """Updates the password of the given key and saves to the database"""
        cert = update_password(key.keyvalue, password, newpassword)
        async with self.spec.provide_session(self.config) as session:
            _ = await session.execute(
                UPDATE_PASSWORD_SQL, keyvalue=cert, fingerprint=key.fingerprint
            )
        assert cert != key.keyvalue
        key.keyvalue = cert
        return key

    async def certify_key(
        self,
        key: Key | str,
        otherkey: Key | str,
        uids: list[str],
        sig_type: SignatureType = SignatureType.GenericCertification,
        password: str = "",
        oncard: bool = False,
    ) -> Key:
        """Certifies the given uids based on a list of values. Returns the new key.

        :param key: Fingerprint or secret Key object using which we will certify.
        :param other_key: Fingerprint or Key object whom we will certify.
        :param uids: List of uid values which we will certify using the given SignatureType.
        :param sig_type: SignatureType, default is SignatureType.GenericCertification
        :param password: Password of the secret key file or the pin if on card.
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(otherkey, str):  # Means we have a fingerprint
            other_k = await self.get_key(otherkey)
        else:
            other_k = otherkey

        cert = certify_key(
            k.keyvalue,
            other_k.keyvalue,
            sig_type.value,
            uids,
            password.encode("utf-8"),
            oncard,
        )
        # Now if the otherkey is secret, then merge this new public key into the secret key
        if other_k.keytype == KeyType.SECRET:
            cert = merge_keys(other_k.keyvalue, cert, True)
        # first remove the old one
        await self.delete_key(otherkey)
        # Now add back the new updated key
        (
            nuids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = parse_cert_bytes(cert)

        await self._save_key_info_to_db(
            cert,
            nuids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        )
        return await self.get_key(fingerprint)

    async def add_key_file_to_db(
        self,
        fullpath: StrOrBytesPath,
        uids: list[dict[str, Any]],  # pyright: ignore[reportExplicitAny]
        fingerprint: str,
        keytype: bool,
        expirationtime: datetime | None = None,
        creationtime: datetime | None = None,
        subkeys: dict[str, Any] | None = None,  # pyright: ignore[reportExplicitAny]
    ):
        "Populates the internal database of the store from a keyfile"
        if not subkeys:
            subkeys = {}
        with open(fullpath, "rb") as fobj:
            cert = fobj.read()
        await self._save_key_info_to_db(
            cert, uids, fingerprint, keytype, expirationtime, creationtime, subkeys
        )

    async def _save_key_info_to_db(
        self,
        cert: bytes,
        uids: list[dict[str, Any]],  # pyright: ignore[reportExplicitAny]
        fingerprint: str,
        keytype: bool,
        expirationtime: datetime | None,
        creationtime: datetime | None,
        othervalues: dict[str, Any],  # pyright: ignore[reportExplicitAny]
    ):
        "Saves all information given to the SQLite3 database"
        etime = str(expirationtime.timestamp()) if expirationtime else ""
        ctime = str(creationtime.timestamp()) if creationtime else ""
        ktype = 1 if keytype else 0
        subkeys = othervalues["subkeys"]
        mainkeyid = othervalues["keyid"]
        can_primary_sign = othervalues["can_primary_sign"]
        async with self.spec.provide_session(self.config) as session:
            # First let us check if a key already exists
            fromdb = await session.fetch_one_or_none(
                SELECT_KEY_BY_FINGERPRINT_SQL, fingerprint=fingerprint
            )
            if fromdb:  # Means a key is there in the db
                key_id = fromdb["id"]
                if (
                    fromdb["keytype"] == 0
                ):  # only update if there is a public key in the store
                    key = await self.get_key(fingerprint)
                    newcert = merge_keys(key.keyvalue, cert, False)
                    uids, _fp, _kt, et, ct, othervalues = parse_cert_bytes(newcert)
                    etime = str(et.timestamp()) if et else ""
                    ctime = str(ct.timestamp()) if ct else ""
                else:  # Means another secret to replace
                    # We will not do anything, if you want reimport for a secret key
                    # delete the old one, and import the new one
                    raise SameKeyError(f"{fingerprint}")
                _ = await session.execute(
                    UPDATE_KEY_SQL, cert, ktype, etime, ctime, key_id
                )
            else:
                # Now insert the new key and get the key_id with returning, if supported
                # that's the reason of the try except block
                try:
                    k = await session.fetch_one_or_none(
                        INSERT_KEY_SQL,
                        keyvalue=cert,
                        fingerprint=fingerprint,
                        keyid=mainkeyid,
                        keytype=ktype,
                        expiration=etime,
                        creation=ctime,
                        can_primary_sign=can_primary_sign,
                    )
                    key_id = k["id"]
                except SQLSpecError as e:
                    logger.error(f"Error inserting key: {e}")
                    raise e
            # Now let us add the subkey and keyid details
            for subkey in subkeys:
                ctime = str(subkey[2].timestamp()) if subkey[2] else ""
                etime = str(subkey[3].timestamp()) if subkey[3] else ""
                _ = await session.execute(
                    INSERT_SUBKEYS_SQL,
                    key_id=key_id,
                    fingerprint=subkey[1],
                    keyid=subkey[0],
                    expiration=etime,
                    creation=ctime,
                    keytype=subkey[4],
                    revoked=subkey[5],
                )

            # TODO: Now for each of the uid, add to the right dictionary
            for uid_keyname in ["name", "value", "email", "uri"]:
                tablename = f"uid{uid_keyname}s"
                # First delete all old ones
                _ = await session.execute(
                    f"DELETE from {tablename} where key_id=:key_id", key_id=key_id
                )
            for uid in uids:
                # First we will insert the value
                if "value" in uid and uid["value"]:
                    revoked = 1 if uid["revoked"] else 0
                    value_id = await session.fetch_value(
                        INSERT_UIDVALUES_SQL,
                        value=uid["value"],
                        revoked=revoked,
                        key_id=key_id,
                    )
                    # After we added the value, we should check for certification
                    if len(uid["certifications"]) > 0:
                        for ucert in uid["certifications"]:
                            ctime = (
                                str(ucert["creationtime"].timestamp())
                                if ucert["creationtime"]
                                else ""
                            )
                            uc = await session.fetch_one(
                                INSERT_UIDCERTS_SQL,
                                ctype=ucert["certification_type"],
                                creation=ctime,
                                key_id=key_id,
                                value_id=value_id,
                            )
                            # This is the ID of the certification we just added to the database
                            ucert_id = uc["id"]
                            # Now time to loop over the details and add them
                            for citem in ucert["certification_list"]:
                                # citem is like [('fingerprint', 'F7FC698FAAE2D2EFBECDE98ED1B3ADC0E0238CA6'), ('keyid', 'D1B3ADC0E0238CA6')]
                                _ = await session.execute(
                                    INSERT_UIDCERTLIST_SQL,
                                    value=citem[1],
                                    datatype=citem[0],
                                    key_id=key_id,
                                    value_id=value_id,
                                    cert_id=ucert_id,
                                )
                else:
                    # If no value, then we can skip the rest
                    continue
                for uid_keyname in ["name", "email", "uri"]:
                    if uid_keyname in uid and uid[uid_keyname]:
                        tablename = f"uid{uid_keyname}s"
                        value = uid[uid_keyname]
                        sql = f"INSERT INTO {tablename} (value, key_id, value_id) values (:value, :key_id, :value_id)"
                        _ = await session.execute(
                            sql, value=value, key_id=key_id, value_id=value_id
                        )

    async def __contains__(self, other: str | Key) -> bool:
        """Checks if a Key object of fingerprint str exists in the keystore or not.

        :param other: Either fingerprint as str or `Key` object.
        :returns: boolean result
        """
        fingerprint: str = ""
        if isinstance(other, str):
            fingerprint = other
        else:
            fingerprint = other.fingerprint
        try:
            if await self.get_key(fingerprint):
                return True
        except KeyNotFoundError:
            return False
        return False

    async def update_expiry_in_subkeys(
        self, key: Key, subkeys: list[str], expiration: datetime | None, password: str
    ) -> Key:
        """Updates the expiry date for the given subkeys, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param subkeys: List of strings for subkey fingerprints.
        :param expiration: datetime.datetime for the new expiration date and time, can not be none
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")

        fingerprint = key.fingerprint

        if expiration:
            etime = expiration.timestamp()
            now = datetime.now()
            # We need to send in the difference between expiration time and now
            etime = int(etime - now.timestamp())
        else:
            raise ValueError("The expiration must not be none.")

        # Now get the key material
        newcert = update_subkeys_expiry_in_cert(key.keyvalue, subkeys, etime, password)
        # We only need get the subkeys and get the expiration time from them
        (_, _, _, _, _, othervalues) = parse_cert_bytes(newcert)
        newsubkeys = othervalues["subkeys"]
        # Now save the key
        async with self.spec.provide_session(self.config) as session:
            # First let us update the actual keyvalue
            _ = await session.execute(UPDATE_PASSWORD_SQL, (newcert, key.fingerprint))
            # Now we need the key_id from the database table
            # removed seems unused
            # Now let us add the subkey and keyid details
            for subkey in newsubkeys:
                etime_str = str(subkey[3].timestamp()) if subkey[3] else ""
                _ = await session.execute(
                    UPDATE_SUBKEY_EXPIRATION_SQL,
                    (etime_str, subkey[1]),
                )
        # Regnerate the key object and return it
        return await self.get_key(fingerprint)

    async def update_expiry_in_primary(
        self, key: Key, expiration: datetime | None, password: str
    ) -> Key:
        """Updates the expiry date for the primary key, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param expiration: datetime.datetime for the new expiration date and time, can not be none
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")

        fingerprint = key.fingerprint

        if expiration:
            etime = expiration.timestamp()
            now = datetime.now()
            # We need to send in the difference between expiration time and now
            etime = int(etime - now.timestamp())
        else:
            raise ValueError("The expiration must not be none.")

        # Now get the key material
        newcert = update_primary_expiry_in_cert(key.keyvalue, etime, password)

        # We only need get the subkeys and get the expiration time from them
        _, _, _, expirytime, _, _ = parse_cert_bytes(newcert)

        if expirytime:
            etime_str = str(expirytime.timestamp())
        else:
            etime_str = None
        async with self.spec.provide_session(self.config) as session:
            _ = await session.execute(
                UPDATE_KEY_EXPIRATION_SQL, expiration=etime_str, fingerprint=fingerprint
            )
        return await self.get_key(fingerprint)

    async def add_userid(self, key: Key, userid: str, password: str) -> Key:
        """Adds a new user id to the given key, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param uid: The string value to add the keybobject
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")
        # A list of UID values which is already in the database
        olduids = [uid["value"] for uid in key.uids]
        # Now add the new userid to the cert in binary formart
        newcert = add_uid_in_cert(key.keyvalue, userid.encode("utf-8"), password)

        # Now we will parse the new cert bytes so that we can get the actual value for the user id
        # Expensive, but works.
        (
            uids,
            fingerprint,
            keytype,
            _expirationtime,
            _creationtime,
            _othervalues,
        ) = parse_cert_bytes(newcert)
        # To make sure we actually have a secret key
        assert keytype is True
        # Let us write the new keydata to the disk
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "wb") as fobj:
            _ = fobj.write(newcert)
        async with self.spec.provide_session(self.config) as session:
            # First let us update the actual keyvalue
            _ = await session.execute(
                UPDATE_PASSWORD_SQL, keyvalue=newcert, fingerprint=key.fingerprint
            )
            # Now we need the key_id from the database table
            key_id = await session.fetch_value(
                SELECT_KEYID_SQL, fingerprint=key.fingerprint
            )
            # Now loop through the new userids and find the new one
            for uid in uids:
                if "value" in uid and uid["value"]:
                    # First check if we are already there in the old list or not.
                    if uid["value"] in olduids:
                        continue
                    # Ok, now we have a new user id, we can start adding this value to the database
                    # this next line does not make sense for a new user id :)
                    revoked = 1 if uid["revoked"] else 0
                    value_id = await session.fetch_value(
                        INSERT_UIDVALUES_SQL,
                        value=uid["value"],
                        revoked=revoked,
                        key_id=key_id,
                    )
                else:
                    # If no value, then we can skip the rest
                    continue
                for uid_keyname in ["name", "email", "uri"]:
                    if uid_keyname in uid and uid[uid_keyname]:
                        tablename = f"uid{uid_keyname}s"
                        value = uid[uid_keyname]
                        sql = f"INSERT INTO {tablename} (value, key_id, value_id) values (:value, :key_id, :value_id)"
                        _ = await session.execute(
                            sql, value=value, key_id=key_id, value_id=value_id
                        )
        # Regnerate the key object and return it
        return await self.get_key(fingerprint)

    async def revoke_userid(self, key: Key, userid: str, password: str) -> Key:
        """Revokes the given user id to the given key, saves on the database. Then returns the modified key object

        :param key: The secret key object
        :param userid: The string value to add the keybobject
        :param password: The password for the secret key

        :returns: Key object
        """
        if key.keytype != KeyType.SECRET:
            raise ValueError(f"The {key} is not a secret key.")
        # Now revoke the given userid to the cert in binary formart
        newcert = revoke_uid_in_cert(key.keyvalue, userid.encode("utf-8"), password)

        # Now we will parse the new cert bytes so that we can get the actual value for the user id
        # Expensive, but works.
        (
            _uids,
            fingerprint,
            keytype,
            _expirationtime,
            _creationtime,
            _othervalues,
        ) = parse_cert_bytes(newcert)
        # To make sure we actually have a secret key
        assert keytype is True
        # Let us write the new keydata to the disk
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "wb") as fobj:
            _ = fobj.write(newcert)
        async with self.spec.provide_session(self.config) as session:
            # First let us update the actual keyvalue
            _ = await session.execute(
                UPDATE_PASSWORD_SQL, keyvalue=newcert, fingerprint=key.fingerprint
            )
            # Now loop through the new userids and find the new one
            value_id = await session.fetch_value(
                SELECT_UIDVALUES_SQL, fingerprint=key.fingerprint, value=userid
            )
            # Now we will mark this userid as revoked
            revoked = 1
            _revoked = await session.fetch(
                UPDATE_REVOKED_SQL, revoked=revoked, key_id=value_id
            )
        # Regnerate the key object and return it
        return await self.get_key(fingerprint)

    async def import_key(self, keypath: str | Path, onplace: bool = False) -> Key:  # pyright: ignore[reportUnusedParameter]
        """Imports a given key from the given file path.

        :param keypath: Path to the pgp key file, either string or Path object.
        :param onplace: Default value is False, if True means the keyfile is in the right directory.
        """
        # TODO: onplace not used
        if isinstance(keypath, Path):
            path = str(keypath)
        else:
            path = str(keypath)
        keydata = parse_cert_file(path)
        (
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        ) = keydata
        await self.add_key_file_to_db(
            keypath,
            uids,
            fingerprint,
            keytype,
            expirationtime,
            creationtime,
            othervalues,
        )
        return await self.get_key(fingerprint)

    async def details(self):
        "Returns tuple of (number_of_public, number_of_secret_keys)"
        async with self.spec.provide_session(self.config) as session:
            row = session.fetch_one(SELECT_PUB_PRIV_COUNT_SQL)
            return row["public"], row["secret"]

    async def get_key(self, fingerprint: str) -> Key:
        """Finds an existing public key based on the fingerprint. If the key can not be found on disk, then raises OSError.

        :param fingerprint: The fingerprint as str.
        """
        r = await self._internal_get_key(fingerprint)
        return r[0]

    async def _internal_get_key(
        self, fingerprint: str = "", key_id: str | None = None, allkeys: bool = False
    ):
        async with self.spec.provide_session(self.config) as session:
            keys = None
            if fingerprint:
                keys = await session.execute(
                    SELECT_KEY_BY_FINGERPRINT_SQL,
                    fingerprint=fingerprint,
                )
            elif key_id:
                keys = await session.execute(SELECT_KEY_BY_ID_SQL, keyid=key_id)
            elif allkeys:  # means get all keys
                keys = await session.fetch(SELECT_ALL_KEYS)
            return await self._internal_build_key_list(keys)

    async def get_keys_by_keyid(self, keyid: str):
        "Returns a list of keys for a given KeyID"
        # TODO: This has bad SQL, we can improve in future.
        list_of_db_ids = set()
        async with self.spec.provide_session(self.config) as session:
            rows = await session.fetch(SELECT_KEY_BY_KEYID_SQL, keyid=keyid)
            for row in rows:
                list_of_db_ids.add(row["id"])

            rows = await session.fetch(SELECT_SUBKEY_BY_KEYID, keyid=keyid)
            for row in rows:
                list_of_db_ids.add(row["key_id"])
            # Now the final search
            result = []
            for key_id in list(list_of_db_ids):
                rows = await session.fetch(SELECT_KEY_BY_ID_SQL, keyid=key_id)
                result.extend(await self._internal_build_key_list(rows))

            if not result:
                KeyNotFoundError(f"The key with keyid {keyid} is not found.")
            return result

    async def _internal_build_key_list(self, keys: SQLResult | None):
        "Internal method to create a list of keys from db result rows"
        if not keys:
            raise KeyNotFoundError("The key(s) not found in the keystore.")
        finalresult = []
        sql_for_certs = "SELECT value, datatype FROM uidcertlist WHERE cert_id=?"
        for result in keys:
            if result:
                key_id = result["id"]
                cert = result["keyvalue"]
                fingerprint = result["fingerprint"]
                keyid = result["keyid"]
                expirationtime = result["expiration"]
                creationtime = result["creation"]
                keytype = KeyType.SECRET if result["keytype"] else KeyType.PUBLIC
                oncard = result["oncard"]
                can_primary_sign = result["can_primary_sign"]
                primary_on_card = result["primary_on_card"]

                @dataclass
                class UIDValues:
                    "Internal class to help with uidvalues schema"

                    id: int
                    value: str
                    revoked: int

                # Now get the uids
                async with self.spec.provide_session(self.config) as session:
                    sql = "SELECT id, value, revoked FROM uidvalues WHERE key_id=?"
                    uidvalues = await session.fetch(sql, key_id, schema_type=UIDValues)
                    uids = []
                    for row in uidvalues:
                        value_id = row.id
                        revoked = True if row.revoked else False

                        async def _get_one_row_from_table(tablename, value_id):
                            "Internal function to select different uid items"
                            sql = f"SELECT value FROM {tablename} where value_id={value_id}"
                            _result = await session.fetch_one_or_none(sql)
                            if _result:
                                return _result["value"]
                            else:
                                return ""

                        email = await _get_one_row_from_table("uidemails", value_id)
                        name = await _get_one_row_from_table("uidnames", value_id)
                        uri = await _get_one_row_from_table("uiduris", value_id)
                        # Now time to find any certification for the uid value
                        # TODO: Write a join query in future please
                        csql = "SELECT id, ctype, creation FROM uidcerts WHERE key_id=? and value_id=?"
                        certrows = await session.fetch(csql, key_id, value_id)
                        # let us loop over all the certs
                        certifications = []
                        for uidcert in certrows:
                            cert_result = {}
                            cert_result["creationtime"] = uidcert["creation"]
                            cert_result["certification_type"] = uidcert["ctype"]
                            ucertid = uidcert["id"]
                            cert_issuers = await session.execute(
                                sql_for_certs, (ucertid,)
                            )
                            issuers = []
                            for cissuer in cert_issuers:
                                issuers.append((cissuer["datatype"], cissuer["value"]))
                            # now put it in the right place
                            cert_result["certification_list"] = issuers
                            # Now put all the data in the right place
                            certifications.append(cert_result)

                        uids.append(
                            {
                                "value": row.value,
                                "revoked": revoked,
                                "email": email,
                                "name": name,
                                "uri": uri,
                                "certifications": certifications,
                            }
                        )

                # Get the subkeys
                sql = "SELECT fingerprint, keyid, expiration, creation, keytype, revoked FROM subkeys WHERE key_id=?"
                rows = await session.fetch(sql, (key_id,))
                othervalues = {}
                subs = {}
                sort_subkeys = []
                # Each subkey is added as a tuple
                # Remember that there can be many expired subkeys.
                # TODO: Add a value to mark if it was alive at the time of the call
                for row in rows:
                    etime = (
                        datetime.fromtimestamp(float(row["expiration"]))
                        if row["expiration"]
                        else None
                    )
                    ctime = (
                        datetime.fromtimestamp(float(row["creation"]))
                        if row["creation"]
                        else None
                    )
                    subs[row["keyid"]] = (
                        row["fingerprint"],
                        etime,
                        ctime,
                        row["keytype"],
                        bool(row["revoked"]),
                    )
                    sort_subkeys.append(
                        {
                            "keyid": row["keyid"],
                            "fingerprint": row["fingerprint"],
                            "expiration": etime,
                            "creation": ctime,
                            "keytype": row["keytype"],
                            "revoked": bool(row["revoked"]),
                        }
                    )

                sort_subkeys.sort(key=lambda x: to_sort_by_expiry(x), reverse=True)
                othervalues["subkeys"] = subs
                # TODO: We need a testcase for the sorted subkeys
                othervalues["subkeys_sorted"] = sort_subkeys  # type: ignore[assignment]

                finalresult.append(
                    Key(
                        cert,
                        fingerprint,
                        keyid,
                        uids,
                        keytype,
                        expirationtime,
                        creationtime,
                        othervalues,
                        oncard,
                        can_primary_sign,
                        primary_on_card,
                    )
                )
        if finalresult:
            return finalresult
        else:
            raise KeyNotFoundError("The key(s) not found in the keystore.")

    async def get_all_keys(self) -> list[Key]:
        "Returns a list of keys"
        return await self._internal_get_key(allkeys=True)

    async def get_keys(self, qvalue: str, qtype: str = "email") -> list[Key]:
        """Finds an existing public key based on the email, or name or value (in this order). If the key can not be found on disk, then raises OSError.

        :param qvalue: Query text
        :param qtype: The type of the query, default email, other values are value, name or uri.

        :returns: A list of keys or empty list.
        """
        if qtype not in ["email", "value", "uri", "name"]:
            raise CryptoError("We need at least one of the email/name/value/uri.")

        results = []
        unique_fingerprints = {}
        # TODO: Now let us search
        async with self.spec.provide_session(self.config) as session:
            if qtype == "value":
                sql = "SELECT id, key_id FROM uidvalues where value=?"
                rows = await session.fetch(sql, (qvalue,))
                for row in rows:
                    key_id = row["key_id"]
                    r = await self._internal_get_key(key_id=key_id)
                    key = r[0]
                    if key.fingerprint not in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "email":
                sql = "SELECT id, key_id FROM uidemails where value=?"
                rows = await session.fetch(sql, (qvalue,))
                for row in rows:
                    key_id = row["key_id"]
                    r = await self._internal_get_key(key_id=key_id)
                    key = r[0]
                    if key.fingerprint not in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "name":
                sql = "SELECT id, key_id FROM uidenames where value=?"
                rows = await session.fetch(sql, (qvalue,))
                for row in rows:
                    key_id = row["key_id"]
                    r = await self._internal_get_key(key_id=key_id)
                    key = r[0]
                    if key.fingerprint not in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
            elif qtype == "uri":
                sql = "SELECT id, key_id FROM uiduris where value=?"
                rows = await session.fetch(sql, (qvalue,))
                for row in rows:
                    key_id = row["key_id"]
                    r = await self._internal_get_key(key_id=key_id)
                    key = r[0]
                    if key.fingerprint not in unique_fingerprints:
                        unique_fingerprints[key.fingerprint] = True
                        results.append(key)
        return results

    async def create_key(
        self,
        password: str,
        uids: list[str] | str | None = [],
        ciphersuite: Cipher = Cipher.RSA4k,
        creation: datetime | None = None,
        expiration: datetime | None = None,
        subkeys_expiration: bool = False,
        whichkeys: int = 7,
        can_primary_sign: bool = False,
        can_primary_expire: bool = False,
    ) -> Key:
        """Returns a public `Key` object after creating a new key in the store

        :param password: The password for the key as str.
        :param uids: The text for the uid values as List of str. This can be none.
        :param ciphersuite: Default Cipher.RSA4k, other values are Cipher.RSA2k, Cipher.Cv25519
        :param creation: datetime.datetime, default datetime.now() (via rust)
        :param expiration: datetime.datetime, default 0 (Never)
        :param subkeys_expiration: Bool (default False), pass True if you want to set the expiry date to the subkeys.
        :param whichkeys: Decides which all subkeys to generate, 1 (for encryption), 2 for signing, 4 for authentication. Add the numbers for mixed result.
        :param can_primary_sign: Boolean to indicate if the primary key can do signing
        :param can_primary_expire: Boolean to indicate if the primary key can expire, default False.
        """
        if creation:
            ctime = creation.timestamp()
        else:
            ctime = 0

        if expiration:
            etime = expiration.timestamp()
        else:
            etime = 0
        finaluids = []
        if isinstance(uids, str):
            if uids:
                finaluids.append(uids)
        elif isinstance(uids, list):
            finaluids = uids

        public, secret, fingerprint = create_key(
            password,
            finaluids,
            ciphersuite.value,
            int(ctime),
            int(etime),
            subkeys_expiration,
            whichkeys,
            can_primary_sign,
            can_primary_expire,
        )
        # Now save the secret key
        key_filename = os.path.join(self.path, f"{fingerprint}.sec")
        with open(key_filename, "w") as fobj:
            fobj.write(secret)

        key = await self.import_key(key_filename)

        # TODO: should we remove the key_filename from the disk?
        return key

    async def delete_key(self, key: str | Key):
        """Deletes a given key based on the fingerprint.

        :param key: Either str representation of the fingerprint or a Key object
        """
        if isinstance(key, str):
            fingerprint = key
        elif isinstance(key, Key):
            fingerprint = key.fingerprint
        else:
            raise TypeError(f"Wrong datatype for {str(key)}")

        if fingerprint not in self:
            raise KeyNotFoundError(
                "The key for the given fingerprint={fingerprint} is not found in the keystore"
            )
        async with self.spec.provide_session(self.config) as session:
            sql = "SELECT id from keys where fingerprint=?"
            result = await session.fetch_one_or_none(sql, (fingerprint,))
            if result:
                keyid = result["id"]
                _ = await session.execute(
                    "DELETE FROM keys where fingerprint=?", (fingerprint,)
                )
                _ = await session.execute(
                    "DELETE FROM subkeys where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uidvalues where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uidcerts where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uidcertlist where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uidemails where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uidnames where key_id=?", (keyid,)
                )
                _ = await session.execute(
                    "DELETE FROM uiduris where key_id=?", (keyid,)
                )

    async def _find_keys(self, keys: Sequence[Key | str]):
        "To find all the key paths"
        final_keys: list[bytes] = []
        for k in keys:
            if isinstance(k, str):  # Means fingerprint
                key = await self.get_key(k)
                final_keys.append(key.keyvalue)
            else:
                final_keys.append(k.keyvalue)
        return final_keys

    async def encrypt(
        self,
        keys: list[Key] | Key,
        data: str | bytes,
        outputfile: str | bytes = "",
        armor: bool | None = True,
    ):
        """Encrypts the given data with the list of keys and returns the output.

        :param keys: List of fingerprints or Key objects
        :param data: data to be encrtypted, either str or bytes
        :param outputfile: If provided the output will be wriiten in the location.
        :param armor: Default is True, for armored output.
        """
        if not isinstance(keys, list):
            finalkeys = [
                keys,
            ]
        else:
            finalkeys = keys
        final_key_paths = await self._find_keys(finalkeys)
        # Check if we return data
        if isinstance(data, str):
            finaldata = data.encode("utf-8")
        else:
            finaldata = data
        if not outputfile:
            return encrypt_bytes_to_bytes(final_key_paths, finaldata, armor)

        # For encryption to a file
        if isinstance(outputfile, str):
            encrypted_file = outputfile.encode("utf-8")
        else:
            encrypted_file = outputfile

        return encrypt_bytes_to_file(final_key_paths, finaldata, encrypted_file, armor)

    async def decrypt(self, key: str | Key, data: bytes, password: str = "") -> bytes:
        """Decrypts the given bytes and returns plain text bytes.

        :param key: Fingerprint or secret Key object
        :param data: Encrypted data in bytes.
        :param password: Password for the secret key
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        # now let us check if the key is public and has a corresponding smartcard with secret
        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            return decrypt_bytes_on_card(k.keyvalue, data, password.encode("utf-8"))

        # Otherwise, we use the standard ondisk secret
        jp = Johnny(k.keyvalue)
        return jp.decrypt_bytes(data, password)

    async def encrypt_file(
        self,
        keys: Key | list[Key],
        inputfilepath: StrOrBytesPath | BinaryIO,
        outputfilepath: str | bytes,
        armor: bool = True,
    ):
        """Encrypts the given data with the list of keys and writes in the output file.

        :param keys: List of fingerprints or Key objects
        :param inputfilepath: Path of the input file to be encrypted
        :param outputfilepath: output file path
        :param armor: Default is True, for armored output.
        """
        use_filehandler = False
        fh = None

        # This is when we receive str
        if isinstance(inputfilepath, str):
            if not os.path.exists(inputfilepath):
                raise FileNotFoundError(f"{inputfilepath} can not be found.")
            inputfile = inputfilepath.encode("utf-8")
        # This is when we receive bytes
        elif isinstance(inputfilepath, bytes):
            if not os.path.exists(inputfilepath):
                raise FileNotFoundError(f"{inputfilepath!r} can not be found.")
            inputfile = inputfilepath
        else:  # This is when we receive opened file handler
            fh = inputfilepath
            use_filehandler = True
            inputfile = b""  # just to avoid linter complaints

        if not isinstance(keys, list):
            finalkeys = [
                keys,
            ]
        else:
            finalkeys = keys
        final_key_paths = await self._find_keys(finalkeys)  # pyright: ignore[reportUnknownVariableType]

        # For encryption to a file
        if isinstance(outputfilepath, str):
            encrypted_file = outputfilepath.encode("utf-8")
        else:
            encrypted_file = outputfilepath

        if not use_filehandler:
            encrypt_file_internal(final_key_paths, inputfile, encrypted_file, armor)
        else:
            assert fh is not None
            encrypt_filehandler_to_file(final_key_paths, fh, encrypted_file, armor)
        return True

    async def decrypt_file(
        self,
        key: str | Key,
        encrypted_path: StrOrBytesPath | BinaryIO,
        outputfile: str,
        password: str = "",
    ) -> bool | bytes:
        """Decryptes the given file to the output path.

        :param key: Fingerprint or secret Key object
        :param encrypted_path:: Path of the encrypted file, or the opened file handler in binary mode
        :param outputfile: Decrypted output file path as str
        :param password: Password for the secret key
        """
        use_filehandler = False
        fh = None
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(encrypted_path, str):
            inputfile = encrypted_path.encode("utf-8")
        elif isinstance(encrypted_path, bytes):
            inputfile = encrypted_path
        else:
            fh = encrypted_path
            use_filehandler = True
            inputfile = b""  # just to avoid linter complaints

        if isinstance(outputfile, str):
            outputpath = outputfile.encode("utf-8")
        else:
            outputpath = outputfile

        # now let us check if the key is public and has a corresponding smartcard with secret
        if k.keytype == KeyType.PUBLIC and k.oncard is not None:
            if use_filehandler:
                assert fh is not None
                return decrypt_filehandler_on_card(
                    k.keyvalue, fh, outputpath, password.encode("utf-8")
                )
            else:
                return decrypt_file_on_card(
                    k.keyvalue, inputfile, outputpath, password.encode("utf-8")
                )

        jp = Johnny(k.keyvalue)
        if not use_filehandler:
            return jp.decrypt_file(inputfile, outputpath, password)
        else:
            assert fh is not None
            return jp.decrypt_filehandler(fh, outputpath, password)

    async def sign_detached(
        self, key: str | Key, data: str | bytes, password: str
    ) -> str:
        """Signs the given data with the key.

        :param key: Fingerprint or secret Key object
        :param data: Data to be signed.
        :param password: Password of the secret key file.

        :returns: The signature as string
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(data, str):
            data = data.encode("utf-8")

        if k.keytype == KeyType.PUBLIC and not k.oncard:
            return sign_bytes_detached_on_card(
                k.keyvalue, data, password.encode("utf-8")
            )

        jp = Johnny(k.keyvalue)
        return jp.sign_bytes_detached(data, password)

    async def verify(
        self, key: str | Key, data: str | bytes, signature: str | None
    ) -> bool:
        """Verifies the given data and the signature

        :param key: Fingerprint or public Key object
        :param data: Data to be signed.
        :param signature: Signature text

        :returns: Boolean
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(data, str):
            data = data.encode("utf-8")
        jp = Johnny(k.keyvalue)

        if signature:
            return jp.verify_bytes_detached(data, signature.encode("utf-8"))
        else:
            return jp.verify_bytes(data)

    async def sign_file(
        self,
        key: str | Key,
        filepath: str | bytes,
        outputpath: str | bytes,
        password: str,
        cleartext: bool = False,
    ) -> bool:
        """Signs the given input file with key and saves in the outputpath.

        :param key: Fingerprint or secret Key object, public key in case card based operation.
        :param filepath: str value of the path to the file.
        :param outputpath: str value of the path to the output signed file.
        :param password: Password the secret key file or the user pin of the card
        :param cleartext: If the signed file should be in cleartext or not, default False.

        :returns: Boolean result of the signing operation.
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(filepath, str):
            filepath_in_bytes = filepath.encode("utf-8")
        else:
            filepath_in_bytes = filepath

        if isinstance(outputpath, str):
            outputpath_in_bytes = outputpath.encode("utf-8")
        else:
            outputpath_in_bytes = outputpath

        if k.keytype == KeyType.PUBLIC and not k.oncard:
            result = sign_file_on_card(
                k.keyvalue,
                filepath_in_bytes,
                outputpath_in_bytes,
                password.encode("utf-8"),
                cleartext,
            )

        else:
            jp = Johnny(k.keyvalue)
            result = jp.sign_file(
                filepath_in_bytes, outputpath_in_bytes, password, cleartext
            )

        return result

    async def sign_file_detached(
        self,
        key: str | Key,
        filepath: str | bytes,
        password: str,
        write: bool = False,
    ):
        """Signs the given data with the key. It also writes filename.asc in the same directory of the file as the signature if write value is True.

        :param key: Fingerprint or secret Key object
        :param filepath: str value of the path to the file.
        :param password: Password of the secret key file as str.
        :param write: boolean value (default False), determines if we should write the signature to a file.

        :returns: The signature as string
        """
        signature = ""
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(filepath, str):
            filepath_in_bytes = filepath.encode("utf-8")
        else:
            filepath_in_bytes = filepath

        if k.keytype == KeyType.PUBLIC and not k.oncard:
            signature = sign_file_detached_on_card(
                k.keyvalue, filepath_in_bytes, password.encode("utf-8")
            )

        else:
            jp = Johnny(k.keyvalue)
            signature = jp.sign_file_detached(filepath_in_bytes, password)

        # Now check if we have to write the file on disk
        if write:
            sig_file_name = f"{filepath_in_bytes.decode('utf-8')}.asc"
            with open(sig_file_name, "w") as fobj:
                _ = fobj.write(signature)

        return signature

    async def verify_file_detached(
        self, key: str | Key, filepath: str | bytes, signature_path: StrOrBytesPath
    ):
        """Verifies the given filepath based on the signature file.

        :param key: Fingerprint or public Key object
        :param filepath: File to be verified.
        :param signature_path: Path to the signature file.

        :returns: Boolean
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if not os.path.exists(signature_path):
            raise FileNotFoundError(
                f"The signature file at {signature_path!r} is missing."
            )
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file at {str(filepath)} is missing.")

        # Let us read the signature
        with open(signature_path, "rb") as fobj:
            signature_in_bytes = fobj.read()

        if isinstance(filepath, str):
            filepath = filepath.encode("utf-8")
        jp = Johnny(k.keyvalue)
        return jp.verify_file_detached(filepath, signature_in_bytes)

    async def verify_file(self, key: str | Key, filepath: bytes | str) -> bool:
        """Verifies the given filepath.

        :param key: Fingerprint or public Key object
        :param filepath: File to be verified.

        :returns: Boolean
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file at {str(filepath)} is missing.")

        if isinstance(filepath, str):
            input_filepath = filepath.encode("utf-8")
        else:
            input_filepath = filepath

        jp = Johnny(k.keyvalue)
        return jp.verify_file(input_filepath)

    async def verify_and_extract_bytes(
        self, key: str | Key, data: str | bytes
    ) -> bytes:
        """Verifies the given data and returns the acutal data.

        :param key: Fingerprint or public Key object.
        :param data: Data to be signed.

        :returns: bytes
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if isinstance(data, str):
            data = data.encode("utf-8")
        jp = Johnny(k.keyvalue)

        return jp.verify_and_extract_bytes(data)

    async def verify_and_extract_file(
        self, key: str | Key, filepath: str | bytes, output: bytes
    ) -> bool:
        """Verifies the given signed file and saves the actual data in output.

        :param key: Fingerprint or public Key object.
        :param filepath: Signed file as bytes.
        :param output: Output path for the original content.

        :returns: bool
        """
        if isinstance(key, str):  # Means we have a fingerprint
            k = await self.get_key(key)
        else:
            k = key

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"The file at {str(filepath)} is missing.")

        if isinstance(filepath, str):
            input_filepath = filepath.encode("utf-8")
        else:
            input_filepath = filepath

        if isinstance(output, str):
            outputpath = output.encode("utf-8")
        else:
            outputpath = output
        jp = Johnny(k.keyvalue)

        return jp.verify_and_extract_file(input_filepath, outputpath)

    async def fetch_key_by_fingerprint(self, fingerprint: str):
        """Fetches key from keys.openpgp.org based on the fingerprint.

        :param fingerprint: The fingerprint string without the leading 0x and in upper case.

        :returns: Key object if found or else raises KeyNotFoundError
        """
        # First remove any leading 0x
        if fingerprint.startswith("0x"):
            fingerprint = fingerprint[2:]
        # make it uppercase
        fingerprint = fingerprint.upper()
        url = f"https://keys.openpgp.org/vks/v1/by-fingerprint/{fingerprint}"
        return await self._internal_fetch_from_server(url, fingerprint)

    async def fetch_key_by_email(self, email: str):
        """Fetches key from keys.openpgp.org based on the fingerprint.

        :param email: The email address to search

        :returns: Key object if found or else raises KeyNotFoundError
        """
        # encode the email address
        email = quote(email)
        url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
        return await self._internal_fetch_from_server(url, email)

    async def _internal_fetch_from_server(self, url: str, term: str) -> Key:
        resp = httpx.get(url)
        if resp.status_code == 404:
            raise KeyNotFoundError(
                f"The given search term {term} was found in the server."
            )

        elif resp.status_code == 200:
            cert = resp.text.encode("utf-8")
            (
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            ) = parse_cert_bytes(cert)

            await self._save_key_info_to_db(
                cert,
                uids,
                fingerprint,
                keytype,
                expirationtime,
                creationtime,
                othervalues,
            )
            return await self.get_key(fingerprint)
        else:
            raise FetchingError(f"Server returned: {resp.status_code}")

    async def sync_smartcard(self) -> str:
        """
        Syncs the attached smartcard to the right public keys in the KeyStore.

        :returns: The fingerprint of the primary key.
        """
        fingerprint: str = ""
        data = get_card_details()
        if not data["serial_number"]:
            return "No data found."
        async with self.spec.provide_session(self.config) as session:
            # First let us check if a key already exists
            sql = "SELECT DISTINCT key_id, fingerprint FROM subkeys where fingerprint IN (?, ?, ?)"
            sig_f = convert_fingerprint(data["sig_f"])
            enc_f = convert_fingerprint(data["enc_f"])
            auth_f = convert_fingerprint(data["auth_f"])
            fromdb = await session.fetch_one_or_none(sql, (sig_f, enc_f, auth_f))
            if fromdb:
                # Means we found the main key, now we have to mark it with the serial number of the card
                sql = "UPDATE keys SET oncard=? WHERE id=?"
                _ = await session.execute(
                    sql, (data["serial_number"], fromdb["key_id"])
                )
                sql = "SELECT fingerprint from keys where id=?"
                result = await session.fetch_one(sql, (fromdb["key_id"],))
                # result = cursor.fetchone()
                fingerprint = result["fingerprint"]
            # Now let us see if we can find the primary key on the card
            sql = "SELECT DISTINCT id, fingerprint FROM keys where fingerprint IN (?, ?, ?)"
            sig_f = convert_fingerprint(data["sig_f"])
            enc_f = convert_fingerprint(data["enc_f"])
            auth_f = convert_fingerprint(data["auth_f"])
            fromdb = await session.fetch_one_or_none(sql, (sig_f, enc_f, auth_f))
            if fromdb:
                # Means we found the main key, now we have to mark it with the serial number of the card
                sql = "UPDATE keys SET primary_on_card=? WHERE id=?"
                _ = await session.execute(sql, (data["serial_number"], fromdb["id"]))
                sql = "SELECT fingerprint from keys where id=?"
                _ = await session.execute(sql, (fromdb["id"],))
            result = await session.fetch_one()
            fingerprint = result["fingerprint"]

            return fingerprint

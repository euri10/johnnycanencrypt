import datetime
from pathlib import Path
import shutil

import pytest
from sqlspec import SQLSpec
from sqlspec.adapters.aiosqlite import AiosqliteConfig
import vcr  # pyright: ignore[reportMissingTypeStubs]

import johnnycanencrypt as jce
import johnnycanencrypt.johnnycanencrypt as rjce
from johnnycanencrypt.key import SignatureType
from tests.conftest import BASE_TESTSDIR
from tests.utils import verify_files

DATA = "Kushal loves 🦀"

pytestmark = pytest.mark.anyio

@pytest.fixture
async def ks():
    spec = SQLSpec()
    config = spec.add_config(
        AiosqliteConfig(
            connection_config={"database": BASE_TESTSDIR / "files/store/jce.db"}
        )
    )
    # config = spec.add_config(AsyncpgConfig(connection_config={"dsn": "postgres://postgres:postgres@localhost:5432/postgres"}))
    _ks = await jce.AsyncKeyStore.create(spec=spec, config=config, path=BASE_TESTSDIR / "files/store")
    return _ks


@pytest.fixture
async def tmp_ks(tmp_path: Path):
    dbpath = tmp_path / "jce.db"
    spec = SQLSpec()
    config = spec.add_config(AiosqliteConfig(connection_config={"database": dbpath}))
    # config = spec.add_config(AsyncpgConfig(connection_config={"dsn": "postgres://postgres:postgres@localhost:5432/postgres"}))
    ks = await jce.AsyncKeyStore.create(spec=spec, config=config, path=tmp_path)
    return ks


@pytest.fixture
async def tmp_ks_mixed(tmp_path: Path):
    spec = SQLSpec()
    config = spec.add_config(
        AiosqliteConfig(
            connection_config={"database": BASE_TESTSDIR / "files/store/jce.db"}
        )
    )
    # config = spec.add_config(AsyncpgConfig(connection_config={"dsn": "postgres://postgres:postgres@localhost:5432/postgres"}))
    ks = await jce.AsyncKeyStore.create(spec=spec, config=config, path=tmp_path)
    return ks


async def test_correct_keystore_path(ks: jce.AsyncKeyStore):
    assert ks


# async def test_nonexisting_keystore_path():
#     with pytest.raises(OSError):
#         _ks = jce.AsyncKeyStore(BASE_TESTSDIR / "files2/")
#


async def test_str(tmp_ks: jce.AsyncKeyStore):
    assert str(tmp_ks) == f"<KeyStore dbpath={tmp_ks.config.connection_config}>"


async def test_no_such_key(ks: jce.AsyncKeyStore):
    with pytest.raises(jce.KeyNotFoundError):
        _key = await ks.get_key("A4F388BBB194925AE301F844C52B42177857DD79")
    with pytest.raises(jce.KeyNotFoundError):
        _key = await ks.get_key(None)  # pyright: ignore[reportArgumentType]


async def test_create_primary_key_with_encryption(tmp_ks: jce.AsyncKeyStore):
    newkey = await tmp_ks.create_key(
        "redhat",
        "test key42 <42@example.com>",
        jce.Cipher.RSA4k,
        whichkeys=1,
        can_primary_sign=True,
    )
    assert newkey.can_primary_sign


async def test_key_cipher_details(ks: jce.AsyncKeyStore):
    saved = [
        ("F4F388BBB194925AE301F844C52B42177857DD79", "EdDSA", 256),
        ("102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F", "EdDSA", 256),
        ("85B67F139D835FA56BA703DB5A7A1560D46ED4F6", "ECDH", 256),
    ]
    key = await ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    result = rjce.get_key_cipher_details(key.keyvalue)
    assert saved == result


async def test_keystore_lifecycle(tmp_ks: jce.AsyncKeyStore):
    # Now create a fresh db
    newkey = await tmp_ks.create_key(
        "redhat", "test key1 <email@example.com>", jce.Cipher.RSA4k
    )
    # the default key must be of secret
    assert newkey.keytype == jce.KeyType.SECRET

    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "hellopublic.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))
    # Now check the numbers of keys in the store
    assert (2, 2) == await tmp_ks.details()

    await tmp_ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert (2, 1) == await tmp_ks.details()

    # Now verify email cache
    key_via_fingerprint = await tmp_ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys_via_emails = await tmp_ks.get_keys(qvalue="kushaldas@gmail.com", qtype="email")
    assert len(keys_via_emails) == 1
    assert key_via_fingerprint == keys_via_emails[0]

    # Also verify that kushal's primary key can sign
    assert key_via_fingerprint.can_primary_sign

    # Now verify name cache
    key_via_fingerprint = await tmp_ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    keys_via_names = await tmp_ks.get_keys(
        qvalue="Test User2 <random@example.com>", qtype="value"
    )
    assert len(keys_via_names) == 1
    assert key_via_fingerprint == keys_via_names[0]


async def test_keystore_contains_key(tmp_ks: jce.AsyncKeyStore):
    "verifies __contains__ method for keystore"
    keypath = BASE_TESTSDIR / "files" / "store" / "secret.asc"
    k = await tmp_ks.import_key(keypath)
    _, fingerprint, _keytype, _exp, _ctime, _othervalues = jce.parse_cert_file(
        str(keypath)
    )

    # First only the fingerprint
    assert fingerprint in tmp_ks
    # Next the Key object
    assert k in tmp_ks
    # This should be false
    assert "1111111" not in tmp_ks


async def test_keystore_details(ks: jce.AsyncKeyStore):
    assert (1, 2) == await ks.details()


async def test_keystore_keyids(ks: jce.AsyncKeyStore):
    key = await  ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert key.keyid == "D8219C8C43F6C5E1"


async def test_keystore_get_via_keyids(ks: jce.AsyncKeyStore):
    key =await ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    keys =await ks.get_keys_by_keyid("FB82AA5D326DA75D")  # pyright: ignore[reportUnknownVariableType]
    assert len(keys) == 1  # pyright: ignore[reportUnknownArgumentType]
    assert key == keys[0]


async def test_keystore_key_uids(ks: jce.AsyncKeyStore):
    key =await ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    assert "kushal@fedoraproject.org" == key.uids[0]["email"]
    assert "mail@kushaldas.in" == key.uids[-1]["email"]


async def test_key_password_change(tmp_ks: jce.AsyncKeyStore):
    k = await tmp_ks.import_key(BASE_TESTSDIR / "files" / "store" / "secret.asc")
    k2 = await tmp_ks.update_password(k, "redhat", "byebye")
    _data = await tmp_ks.sign_detached(k2, b"hello", "byebye")


async def test_key_deletion(tmp_ks: jce.AsyncKeyStore):
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))
    k = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "hellopublic.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "hellosecret.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))
    assert (1, 2) == await tmp_ks.details()

    await tmp_ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert (1, 1) == await tmp_ks.details()

    # Now send in a Key object
    await tmp_ks.delete_key(k)
    assert (0, 1) == await tmp_ks.details()
    with pytest.raises(jce.KeyNotFoundError):
        await tmp_ks.delete_key("11111")

    # Can not use any random data type
    with pytest.raises(TypeError):
        await tmp_ks.delete_key(2441139)  # pyright: ignore[reportArgumentType]


# https://github.com/kushaldas/johnnycanencrypt/issues/161
async def test_key_deletion_cleanup(tmp_ks: jce.AsyncKeyStore):
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))
    await tmp_ks.delete_key("F4F388BBB194925AE301F844C52B42177857DD79")
    async with tmp_ks.spec.provide_session(tmp_ks.config) as session:
        # Verify all subkeys should be deleted
        sql = "SELECT * from subkeys"
        fromdb = await session.fetch_one_or_none(sql)
        assert not fromdb


async def test_key_equality(ks: jce.AsyncKeyStore):
    key =await ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert key.fingerprint == "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"


async def test_ks_update_expiry_time_for_subkeys(tmp_ks: jce.AsyncKeyStore):
    "Updates expiry time for a given subkey"
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "hellosecret.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))

    key = await tmp_ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    subkeys = [
        "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F",
    ]
    newexpiration = datetime.datetime(2050, 10, 25, 10)
    newkey = await tmp_ks.update_expiry_in_subkeys(key, subkeys, newexpiration, "redhat")
    assert newkey.othervalues
    for _, skey in newkey.othervalues["subkeys"].items():  # pyright: ignore[reportAny]
        if skey[0] == "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F":
            date = skey[1]  # pyright: ignore[reportAny]
            assert date.date() == datetime.date(2050, 10, 25)  # pyright: ignore[reportAny]

    with pytest.raises(ValueError):
        newkey = await tmp_ks.update_expiry_in_subkeys(key, subkeys, None, "redhat")


async def test_ks_update_expiry_time_for_primary(tmp_ks: jce.AsyncKeyStore):
    "Updates expiry time for a given primary key"
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "hellosecret.asc"))
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))

    key = await tmp_ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    newexpiration = datetime.datetime(2050, 10, 25, 10)
    newkey = await tmp_ks.update_expiry_in_primary(key, newexpiration, "redhat")
    assert newkey.expirationtime
    assert newkey.expirationtime.date() == datetime.date(2050, 10, 25)


async def test_ks_encrypt_decrypt_bytes(ks: jce.AsyncKeyStore):
    "Encrypts and decrypt some bytes"
    public_key =await ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    encrypted =await ks.encrypt(public_key, DATA)
    assert isinstance(encrypted, bytes)
    assert encrypted.startswith(b"-----BEGIN PGP MESSAGE-----\n")
    secret_key =await ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_bytes =await  ks.decrypt(secret_key, encrypted, password="redhat")
    decrypted_text = decrypted_bytes.decode(
        "utf-8"
    )
    assert DATA == decrypted_text


async def test_ks_encrypt_decrypt_bytes_multiple_recipients(ks: jce.AsyncKeyStore):
    "Encrypts and decrypt some bytes"
    key1 =await ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 =await ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    encrypted =await ks.encrypt([key1, key2], DATA)
    assert isinstance(encrypted, bytes)
    assert encrypted.startswith(b"-----BEGIN PGP MESSAGE-----\n")
    secret_key1 =await ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    decrypted_bytes =await ks.decrypt(secret_key1, encrypted, password="redhat")
    decrypted_text = decrypted_bytes.decode(
        "utf-8"
    )
    assert DATA == decrypted_text
    secret_key2 =await ks.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_bytes =await ks.decrypt(secret_key2, encrypted, password="redhat")
    decrypted_text =decrypted_bytes.decode(
        "utf-8"
    )

    assert DATA == decrypted_text


async def test_ks_encrypt_decrypt_bytes_to_file(tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path):
    "Encrypts and decrypt some bytes"
    outputfile = tmp_path / "encrypted.asc"
    secret_key = await tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert await tmp_ks_mixed.encrypt(secret_key, DATA, outputfile=str(outputfile))
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key =await  tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_bytes =await  tmp_ks_mixed.decrypt(
        secret_key, encrypted, password="redhat"
    )
    decrypted_text= decrypted_bytes.decode("utf-8")
    assert DATA == decrypted_text


async def test_ks_encrypt_decrypt_bytes_to_file_multiple_recipients(
    tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path
):
    "Encrypts and decrypt some bytes"

    outputfile = tmp_path / "encrypted.asc"
    key1 = await tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 =  await tmp_ks_mixed.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    assert await tmp_ks_mixed.encrypt([key1, key2], DATA, outputfile=str(outputfile))
    with open(outputfile, "rb") as fobj:
        encrypted = fobj.read()
    secret_key = await tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    decrypted_bytes = await tmp_ks_mixed.decrypt(
        secret_key, encrypted, password="redhat"
    )
    decrypted_text = decrypted_bytes.decode("utf-8")
    assert DATA == decrypted_text


async def test_ks_encrypt_decrypt_file(tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    public_key = await tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    assert  await tmp_ks_mixed.encrypt_file(public_key, str(inputfile), str(output))
    secret_key = await tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    _ = tmp_ks_mixed.decrypt_file(
        secret_key, str(output), str(decrypted_output), password="redhat"
    )
    verify_files(inputfile, decrypted_output)


async def test_ks_encrypt_decrypt_filehandler(tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    public_key =await  tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(inputfile, "rb") as fobj:
        assert tmp_ks_mixed.encrypt_file(public_key, fobj, str(output))
    secret_key =await  tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    with open(output, "rb") as fobj:
        _ = tmp_ks_mixed.decrypt_file(
            secret_key, fobj, str(decrypted_output), password="redhat"
        )
    verify_files(inputfile, decrypted_output)


async def test_ks_encrypt_decrypt_file_multiple_recipients(
    tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path
):
    "Encrypts and decrypt some bytes"
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    output = tmp_path / "text-encrypted.pgp"
    decrypted_output = tmp_path / "text.txt"

    key1 =await  tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    key2 =await  tmp_ks_mixed.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    _encrypted =await  tmp_ks_mixed.encrypt_file([key1, key2], str(inputfile), str(output))
    secret_key1 =await  tmp_ks_mixed.get_key("F51C310E02DC1B7771E176D8A1C5C364EB5B9A20")
    _ = tmp_ks_mixed.decrypt_file(
        secret_key1, str(output), str(decrypted_output), password="redhat"
    )
    verify_files(inputfile, decrypted_output)
    secret_key2 =await  tmp_ks_mixed.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    _ = tmp_ks_mixed.decrypt_file(
        secret_key2, str(output), str(decrypted_output), password="redhat"
    )
    verify_files(inputfile, decrypted_output)


async def test_ks_sign_data(ks: jce.AsyncKeyStore):
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed =await   ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert await ks.verify(key, "hello", signed)


async def test_ks_sign_data_fails(ks: jce.AsyncKeyStore):
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    signed =await  ks.sign_detached(key, "hello", "redhat")
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert not await  ks.verify(key, "hello2", signed)


async def test_ks_sign_verify_file_detached(tmp_ks_mixed: jce.AsyncKeyStore, tmp_path: Path):
    inputfile = BASE_TESTSDIR / "files" / "text.txt"
    _ = shutil.copy(inputfile, tmp_path)
    key = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    file_to_be_signed = tmp_path / "text.txt"
    signed =await  tmp_ks_mixed.sign_file_detached(
        key, str(file_to_be_signed), "redhat", write=True
    )
    assert signed.startswith("-----BEGIN PGP SIGNATURE-----\n")
    assert tmp_ks_mixed.verify_file_detached(
        key, str(file_to_be_signed), str(file_to_be_signed) + ".asc"
    )


async def test_ks_userid_signing(tmp_ks: jce.AsyncKeyStore):
    # Now create a fresh db
    k = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"))
    t2 = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))

    # now let us sign the keys in kushal's uids
    k = await tmp_ks.certify_key(
        t2,
        k,
        ["Kushal Das <kushaldas@gmail.com>", "Kushal Das <kushal@fedoraproject.org>"],
        SignatureType.PersonaCertification,
        password="redhat",
    )
    # k now contains the new updated key
    for uid in k.uids:
        if (
            uid["value"] == "Kushal Das <kushaldas@gmail.com>"
            or uid["value"] == "Kushal Das <kushal@fedoraproject.org>"
        ):
            certs = uid["certifications"]
            # Only the new certification
            assert len(certs) == 1
            cert: dict[str, str | list[tuple[str, str]]] = certs[0]
            assert cert["certification_type"] == "persona"
            for data in cert["certification_list"]:
                if data[0] == "fingerprint":
                    assert data[1] == "F4F388BBB194925AE301F844C52B42177857DD79"
                if data[0] == "keyid":
                    assert data[1] == "C52B42177857DD79"
        else:
            assert len(uid["certifications"]) == 0


async def test_ks_creation_expiration_time(tmp_ks: jce.AsyncKeyStore):
    """
    Tests via Kushal's key and a new key
    """
    # These two are known values from kushal
    etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
    ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
    # First let us check from the file
    keypath = BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc"
    k = await tmp_ks.import_key(keypath)
    assert k.expirationtime
    assert k.creationtime
    assert etime.date() == k.expirationtime.date()
    assert ctime.date() == k.creationtime.date()

    # now with a new key and creation time
    ctime = datetime.datetime(2010, 10, 10, 20, 53, 47)
    newk =await  tmp_ks.create_key(
        "redhat", "Another test key", ciphersuite=jce.Cipher.Cv25519, creation=ctime
    )
    assert newk.creationtime
    assert ctime.date() == newk.creationtime.date()
    assert not newk.expirationtime

    # Now both creation and expirationtime for primary key
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2025, 12, 15, 20, 53, 47)
    newk = await tmp_ks.create_key(
        "redhat",
        "Another test key",
        creation=ctime,
        expiration=etime,
        can_primary_expire=True,
    )
    assert newk.creationtime
    assert newk.expirationtime
    assert ctime.date() == newk.creationtime.date()
    assert etime.date() == newk.expirationtime.date()

    # Now both creation and expirationtime for subkeys
    ctime = datetime.datetime(2008, 10, 10, 20, 53, 47)
    etime = datetime.datetime(2029, 12, 15, 20, 53, 47)
    newk = await tmp_ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        creation=ctime,
        expiration=etime,
        subkeys_expiration=True,
    )
    assert newk.creationtime
    assert newk.othervalues
    assert ctime.date() == newk.creationtime.date()
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()

    # Now only providing expirationtime for subkeys
    etime = datetime.datetime(2030, 6, 5, 20, 53, 47)
    newk = await tmp_ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        expiration=etime,
        subkeys_expiration=True,
    )
    assert newk.creationtime
    assert datetime.datetime.now().date() == newk.creationtime.date()
    assert not newk.expirationtime
    assert newk.othervalues
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()

    # Now verify both subkeys and primary can expire
    etime = datetime.datetime(2030, 6, 5, 20, 53, 47)
    newk = await tmp_ks.create_key(
        "redhat",
        "Test key with subkey expiration",
        expiration=etime,
        subkeys_expiration=True,
        can_primary_expire=True,
    )
    assert newk.creationtime
    assert newk.expirationtime
    assert datetime.datetime.now().date() == newk.creationtime.date()
    assert etime.date() == newk.expirationtime.date()
    assert newk.othervalues
    for skeyid, subkey in newk.othervalues["subkeys"].items():
        assert subkey[1].date() == etime.date()


async def test_get_all_keys(ks: jce.AsyncKeyStore):
    keys =await  ks.get_all_keys()
    assert 3 == len(keys)
    # TODO: add more checks here in future


async def test_get_pub_key(ks: jce.AsyncKeyStore):
    """Verifies that we export only the public key part from any key"""
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key =await  ks.get_key(fingerprint)
    # verify that the key is a secret
    assert key.keytype == jce.KeyType.SECRET

    # now get the public key
    pub_key = key.get_pub_key()
    assert pub_key.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")


async def test_add_userid(tmp_ks: jce.AsyncKeyStore):
    """Verifies that we can add uid to a cert"""
    key = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))
    # check that there is only one userid
    assert len(key.uids) == 1

    # now add a new userid
    key2 = await tmp_ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")

    assert key2.fingerprint == key.fingerprint
    assert len(key2.uids) == 2
    assert key2.keytype == jce.KeyType.SECRET


async def test_add_and_revoke_userid(tmp_ks: jce.AsyncKeyStore):
    """Verifies that we can add uid to a cert"""
    key = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "secret.asc"))
    # check that there is only one userid
    assert len(key.uids) == 1

    # now add a new userid
    key2 = await tmp_ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")

    assert key2.fingerprint == key.fingerprint
    assert len(key2.uids) == 2
    assert key2.keytype == jce.KeyType.SECRET
    # because at first all user ids are valid
    for uid in key2.uids:
        assert not uid["revoked"]

    # now let us reove the new user id
    key3 = await tmp_ks.revoke_userid(key2, "Off Spinner <spin@example.com>", "redhat")
    # verify the values
    assert key3.fingerprint == key.fingerprint
    assert len(key3.uids) == 2
    assert key3.keytype == jce.KeyType.SECRET
    for uid in key3.uids:
        if uid["value"] == "Off Spinner <spin@example.com>":
            assert uid["revoked"]
        else:
            assert not uid["revoked"]


async def test_add_userid_fails_for_public(tmp_ks: jce.AsyncKeyStore):
    """Verifies that adding uid to a public key fails"""
    key = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))
    # verify that the key is a secret
    assert len(key.uids) == 1

    # now add a new userid
    with pytest.raises(ValueError):
        _key2 = await tmp_ks.add_userid(key, "Off Spinner <spin@example.com>", "redhat")


async def test_update_subkey_expiry_time(ks: jce.AsyncKeyStore):
    "Updates the expirytime for a given subkey"
    key =await  ks.get_key("F4F388BBB194925AE301F844C52B42177857DD79")
    fps = [
        "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F",
    ]
    newkeyvalue = rjce.update_subkeys_expiry_in_cert(
        key.keyvalue, fps, 60 * 60 * 24, "redhat"
    )
    _, _, _, _, _, othervalues = rjce.parse_cert_bytes(newkeyvalue)
    tomorrow = datetime.date.today() + datetime.timedelta(days=1)
    for skey in othervalues["subkeys"]:
        if skey[1] == "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F":
            date = skey[3]
            assert date.date() == tomorrow


async def test_same_key_import_error(tmp_ks: jce.AsyncKeyStore):
    _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))
    with pytest.raises(rjce.CryptoError):
        _ = await tmp_ks.import_key((BASE_TESTSDIR / "files" / "store" / "public.asc"))


async def test_key_without_uid(tmp_ks: jce.AsyncKeyStore):
    k = await tmp_ks.create_key("redhat")
    uids, _fp, _secret, _et, _ct, _othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 0


async def test_key_with_multiple_uids(tmp_ks: jce.AsyncKeyStore):
    uids = [
        "Kushal Das <kushaldas@gmail.com>",
        "kushal@freedom.press",
        "This is also Kushal",
    ]
    k = await tmp_ks.create_key("redhat", uids)
    uids, fp, secret, et, ct, othervalues = jce.parse_cert_bytes(k.keyvalue)
    assert len(uids) == 3


# async def test_ks_upgrade(tmp_ks: jce.AsyncKeyStore, tmp_path: Path):
#     "tests db upgrade from an old db"
#     # copy db
#     shutil.copy(BASE_TESTSDIR / "files" / "store" / "oldjce.db", tmp_path / "jce.db")
#
#     # First we will check if this db schema is old or not
#     with tmp_ks.spec.provide_session(tmp_ks.config) as session:
#         sql = "SELECT * from dbupgrade"
#         fromdb = session.fetch_one(sql)
#         assert fromdb["upgradedate"] == DB_UPGRADE_DATE
#     # TODO: Now verify the keys inside of the new db, in full.
#
#
# async def test_ks_upgrade_failure(tmp_path: Path):
#     "tests db upgrade failure from an old db because of existing file"
#     shutil.copy(BASE_TESTSDIR / "files" / "store" / "oldjce.db", tmp_path / "jce.db")
#     shutil.copy(
#         BASE_TESTSDIR / "files" / "store" / "oldjce.db", tmp_path / "jce_upgrade.db"
#     )
#     with pytest.raises(RuntimeError):
#         spec = SQLSpec()
#         config = spec.add_config(
#             SqliteConfig(connection_config={"database": tmp_path / "jce.db"})
#         )
#         _ks = jce.AsyncKeyStore(spec=spec, config=config, path=tmp_path)


async def test_get_encrypted_for():
    keyids = rjce.file_encrypted_for(
        str(BASE_TESTSDIR / "files" / "double_recipient.asc")
    )

    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]
    with open(BASE_TESTSDIR / "files" / "double_recipient.asc", "rb") as fobj:
        data = fobj.read()
    keyids = rjce.bytes_encrypted_for(data)
    assert keyids == ["1CF980B8E69E112A", "5A7A1560D46ED4F6"]


async def test_available_subkeys_for_no_expiration(ks: jce.AsyncKeyStore):
    """Verifies that we export only the public key part from any key"""
    fingerprint = "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20"
    key =await  ks.get_key(fingerprint)
    e, s, a = key.available_subkeys()
    assert e
    assert s
    assert not a


async def test_available_subkeys_for_expired(tmp_ks: jce.AsyncKeyStore):
    """Verifies that we export only the public key part from any key"""
    await tmp_ks.import_key(BASE_TESTSDIR / "files" / "store" / "pgp_keys.asc")
    key = await tmp_ks.get_key("A85FF376759C994A8A1168D8D8219C8C43F6C5E1")
    e, s, a = key.available_subkeys()
    assert not e
    assert not s
    assert not a


@vcr.use_cassette(str(BASE_TESTSDIR / "files" / "test_fetch_key_by_fingerprint.yml"))
async def test_fetch_key_by_fingerprint(tmp_ks: jce.AsyncKeyStore):
    key = await tmp_ks.fetch_key_by_fingerprint("EF6E286DDA85EA2A4BA7DE684E2C6E8793298290")
    assert len(key.uids) == 1
    uid = key.uids[0]
    assert uid["email"] == "torbrowser@torproject.org"
    assert uid["name"] == "Tor Browser Developers"


@vcr.use_cassette(
    str(BASE_TESTSDIR / "files" / "test_fetch_nonexistingkey_by_fingerprint.yml")
)
async def test_fetch_nonexistingkey_by_fingerprint(tmp_ks: jce.AsyncKeyStore):
    with pytest.raises(jce.KeyNotFoundError):
        _key = await tmp_ks.fetch_key_by_fingerprint(
            "EF6E286DDA85EA2A4BA7DE684E2C6E8793298291"
        )


@vcr.use_cassette(str(BASE_TESTSDIR / "files" / "test_fetch_key_by_email.yml"))
async def test_fetch_key_by_email(tmp_ks: jce.AsyncKeyStore):
    key = await tmp_ks.fetch_key_by_email("anwesha.srkr@gmail.com")
    assert len(key.uids) == 2
    uid = key.uids[0]
    assert uid["name"] == "Anwesha Das"
    assert key.fingerprint == "2871635BE3B4E5C04F02B848C353BFE051D06C33"


@vcr.use_cassette(
    str(BASE_TESTSDIR / "files" / "test_fetch_nonexistingkey_by_email.yml")
)
async def test_fetch_nonexistingkey_by_email(tmp_ks: jce.AsyncKeyStore):
    with pytest.raises(jce.KeyNotFoundError):
        _fetched = await tmp_ks.fetch_key_by_email("doesnotexists@kushaldas.in")

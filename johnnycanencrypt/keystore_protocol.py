from pathlib import Path
from typing import Any, BinaryIO, Protocol
from datetime import datetime

from sqlspec import SQLSpec, SyncDatabaseConfig
from johnnycanencrypt.key import Key, Cipher, SignatureType, StrOrBytesPath


class KeyStoreProtocol(Protocol):
    def __init__(
        self,
        spec: SQLSpec,
        config: SyncDatabaseConfig[Any, Any, Any],
        path: Path,
    ) -> None: ...
    def update_password(self, key: Key, password: str, newpassword: str) -> Key: ...
    def certify_key(
        self,
        key: Key | str,
        otherkey: Key | str,
        uids: list[str],
        sig_type: SignatureType = SignatureType.GenericCertification,
        password: str = "",
        oncard: bool = False,
    ) -> Key: ...
    def add_key_file_to_db(
        self,
        fullpath,
        uids,
        fingerprint,
        keytype,
        expirationtime=None,
        creationtime=None,
        subkeys=[],
    ): ...
    def update_expiry_in_subkeys(
        self, key: Key, subkeys: list[str], expiration: datetime, password: str
    ) -> Key: ...
    def update_expiry_in_primary(
        self, key: Key, expiration: datetime, password: str
    ) -> Key: ...
    def add_userid(self, key: Key, userid: str, password: str) -> Key: ...
    def revoke_userid(self, key: Key, userid: str, password: str) -> Key: ...
    def import_key(self, keypath: str | Path, onplace: bool = False) -> Key: ...
    def details(self) -> tuple[int, int]: ...
    def get_key(self, fingerprint: str) -> Key: ...
    def get_keys_by_keyid(self, keyid: str) -> list[Key]: ...
    def get_all_keys(self) -> list[Key]: ...
    def get_keys(self, qvalue: str, qtype: str = "email") -> list[Key]: ...
    def create_key(
        self,
        password: str,
        uids: list[str] | str | None = [],
        ciphersuite: Cipher = Cipher.RSA4k,
        creation=None,
        expiration=None,
        subkeys_expiration=False,
        whichkeys=7,
        can_primary_sign=False,
        can_primary_expire=False,
    ) -> Key: ...
    def delete_key(self, key: str | Key): ...
    def encrypt(
        self,
        keys: list[Key] | Key,
        data: str | bytes,
        outputfile: str | bytes = "",
        armor: bool | None = True,
    ) -> bytes | bool: ...
    def decrypt(self, key: str | Key, data: bytes, password: str = "") -> bytes: ...
    def encrypt_file(
        self,
        keys: Key | list[Key],
        inputfilepath: StrOrBytesPath | BinaryIO,
        outputfilepath: str | bytes,
        armor: bool = True,
    ) -> bool: ...
    def decrypt_file(
        self,
        key: str | Key,
        encrypted_path: StrOrBytesPath | BinaryIO,
        outputfile: str,
        password: str = "",
    ) -> bool | bytes: ...
    def sign_detached(
        self, key: str | Key, data: str | bytes, password: str
    ) -> str: ...
    def verify(
        self, key: str | Key, data: str | bytes, signature: str | None
    ) -> bool: ...
    def sign_file(
        self,
        key: str | Key,
        filepath: str | bytes,
        outputpath: str | bytes,
        password,
        cleartext: bool = False,
    ) -> bool: ...
    def sign_file_detached(
        self, key: str | Key, filepath: str | bytes, password: str, write: bool = False
    ) -> str: ...
    def verify_file_detached(
        self, key: str | Key, filepath: str | bytes, signature_path: StrOrBytesPath
    ) -> bool: ...
    def verify_file(self, key: str | Key, filepath: bytes | str) -> bool: ...
    def verify_and_extract_bytes(self, key: str | Key, data: str | bytes) -> bytes: ...
    def verify_and_extract_file(
        self, key: str | Key, filepath: str | bytes, output: bytes
    ) -> bool: ...
    def fetch_key_by_fingerprint(self, fingerprint: str) -> Key: ...
    def fetch_key_by_email(self, email: str) -> Key: ...
    def sync_smartcard(self) -> str: ...

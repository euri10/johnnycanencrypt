
from datetime import datetime
import os
from enum import Enum
from typing import Any, override

from johnnycanencrypt.johnnycanencrypt import TouchMode, get_card_version, get_pub_key


StrOrBytesPath = str| bytes| os.PathLike[str]
class KeyType(Enum):
    PUBLIC = 0
    SECRET = 1


class Cipher(Enum):
    RSA4k = "RSA4k"
    RSA2k = "RSA2k"
    Cv25519 = "Cv25519"


class SignatureType(Enum):
    """This is used for key signing via certification"""

    GenericCertification = 0
    PersonaCertification = 1
    CasualCertification = 2
    PositiveCertification = 3


class Key:
    "Returns a Key object."
    
    keyvalue: bytes
    keytype: KeyType
    keyid: str
    fingerprint: str
    uids: list[dict[str, Any]]  # pyright: ignore[reportExplicitAny]
    expirationtime: datetime | None
    creationtime: datetime | None
    othervalues: dict[str, Any] | None  # pyright: ignore[reportExplicitAny]
    oncard: str
    can_primary_sign: bool
    primary_on_card: str



    def __init__(
        self,
        keyvalue: bytes,
        fingerprint: str,
        keyid: str,
        uids: list[dict[str, str]],
        keytype: KeyType = KeyType.PUBLIC,
        expirationtime: int | None = None,
        creationtime: int | None=None,
        othervalues: dict[str, Any] | None = None,  # pyright: ignore[reportExplicitAny]
        oncard: str = "",
        can_primary_sign: bool = False,
        primary_on_card: str = "",
    ):
        self.keyvalue = keyvalue
        self.keytype = keytype
        self.keyid = keyid
        self.fingerprint = fingerprint
        self.uids = uids
        self.expirationtime = (
            datetime.fromtimestamp(float(expirationtime)) if expirationtime else None
        )
        self.creationtime = (
            datetime.fromtimestamp(float(creationtime)) if creationtime else None
        )
        self.othervalues = othervalues
        self.oncard = oncard
        self.can_primary_sign = can_primary_sign
        self.primary_on_card = primary_on_card

    @override
    def __repr__(self):
        return f"<Key fingerprint={self.fingerprint} type={self.keytype.name}>"

    @override
    def __eq__(self, value: object)-> bool:
        """Two keys are same when fingerprint and keytype matches"""
        if not isinstance(value, Key):
            return NotImplemented

        return self.fingerprint == value.fingerprint and self.keytype == value.keytype

    def get_pub_key(self) -> str:
        "Returns the public key part as string"
        return get_pub_key(self.keyvalue)

    def available_subkeys(self) -> tuple[bool, bool, bool]:
        "Returns bool tuple (enc, signing, auth)"
        if self.othervalues is None:
            return (False, False, False)
        subkeys_sorted = self.othervalues["subkeys_sorted"]  # pyright: ignore[reportAny]
        got_enc = False
        got_sign = False
        got_auth = False
        # Loop over on the subkeys
        for subkey in subkeys_sorted:  # pyright: ignore[reportAny]
            if subkey["revoked"]:
                continue
            # When we don't have an expiration date/time.
            if not subkey["expiration"]:
                if subkey["keytype"] == "encryption":
                    got_enc = True
                    continue
                if subkey["keytype"] == "signing":
                    got_sign = True
                    continue
                if subkey["keytype"] == "authentication":
                    got_auth = True
                    continue
            # When we have an expiration date/time.
            if (
                subkey["expiration"] is not None
                and subkey["expiration"].date() > datetime.now().date()  # pyright: ignore[reportAny]
            ):
                if subkey["keytype"] == "encryption":
                    got_enc = True
                    continue
                if subkey["keytype"] == "signing":
                    got_sign = True
                    continue
                if subkey["keytype"] == "authentication":
                    got_auth = True
                    continue
        # Now return the data
        return (got_enc, got_sign, got_auth)





def get_card_touch_policies() -> list[TouchMode]| None:
    "Get the supported touch policies of the smartcard"
    result: list[TouchMode] = []
    version = get_card_version()
    if version < (4, 2, 0):
        result = []
    elif version < (5, 2, 1):
        result = [TouchMode.On, TouchMode.Off, TouchMode.Fixed]
    elif version >= (5, 2, 1):
        result = [
            TouchMode.On,
            TouchMode.Off,
            TouchMode.Fixed,
            TouchMode.Cached,
            TouchMode.CachedFixed,
        ]
    # Now return the result
    return result

# SPDX-FileCopyrightText: © 2020 Kushal Das <mail@kushaldas.in>
# SPDX-License-Identifier: LGPL-3.0-or-later

"""Top-level package exports.

This module historically contained most of the public API.
Synchronous keystore implementation now lives in `johnnycanencrypt.db.keystore`.
Async keystore lives in `johnnycanencrypt.async_db.keystore`.

We keep re-exports here for backwards compatibility.
"""

from __future__ import annotations

from .async_db.keystore import AsyncKeyStore
from .db.keystore import Cipher, Key, KeyStore, KeyType, SignatureType
from .exceptions import FetchingError, KeyNotFoundError
from .johnnycanencrypt import SameKeyError  # noqa: F401
from .johnnycanencrypt import (  # noqa: F401
    CryptoError,
    Johnny,
    TouchMode,
    create_key,
    encrypt_bytes_to_bytes,
    encrypt_bytes_to_file,
    encrypt_file_internal,
    encrypt_filehandler_to_file,
    get_pub_key,
    merge_keys,
    parse_cert_bytes,
    parse_cert_file,
)
from .utils import DB_UPGRADE_DATE, _get_cert_data  # noqa: F401

__all__ = [
    "AsyncKeyStore",
    "Cipher",
    "CryptoError",
    "FetchingError",
    "Johnny",
    "Key",
    "KeyNotFoundError",
    "KeyStore",
    "KeyType",
    "SameKeyError",
    "SignatureType",
    "TouchMode",
    # functions
    "DB_UPGRADE_DATE",
    "create_key",
    "encrypt_bytes_to_bytes",
    "encrypt_bytes_to_file",
    "encrypt_file_internal",
    "encrypt_filehandler_to_file",
    "get_pub_key",
    "merge_keys",
    "parse_cert_bytes",
    "parse_cert_file",
]

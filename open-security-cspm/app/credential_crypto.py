"""
Encryption for cloud credentials in transit through Redis.

CSPM hands a scan's cloud credentials to its worker through Redis rather than
through Celery task arguments, because task args are persisted in the result
backend. The store it moved them to is the same Redis, which runs with
``--appendonly yes`` -- so an AWS secret access key, an Azure client secret or a
GCP service-account JSON was written in plaintext to the append-only file on the
wildbox_redis_data volume, where it survived both the 5-minute TTL and the
worker's explicit delete until the next AOF rewrite (WILDBO-SEC-02).

Credentials are therefore encrypted before they are written and decrypted by the
worker. The key is held by the service (CSPM_CREDENTIAL_KEY), not by Redis, so
an attacker who obtains the volume, a backup or a snapshot gets ciphertext.

Fernet (AES-128-CBC + HMAC-SHA256) from `cryptography`, which the service already
depends on. If no key is configured the service refuses to start a scan rather
than silently falling back to plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken


class CredentialEncryptionError(RuntimeError):
    """Raised when credentials cannot be encrypted or decrypted."""


def _fernet() -> Fernet:
    """
    Build the Fernet instance from CSPM_CREDENTIAL_KEY.

    Accepts either a urlsafe-base64 32-byte Fernet key or an arbitrary
    high-entropy secret, which is stretched to a Fernet key with SHA-256 so an
    operator can reuse the secret-generation tooling without a special format.
    """
    raw = os.getenv("CSPM_CREDENTIAL_KEY") or os.getenv("SECRET_KEY")
    if not raw:
        raise CredentialEncryptionError(
            "CSPM_CREDENTIAL_KEY is not configured. Cloud credentials must not be "
            "written to Redis in plaintext; set CSPM_CREDENTIAL_KEY (32+ random "
            "characters) and restart the service."
        )
    try:
        key = raw.encode()
        if len(base64.urlsafe_b64decode(key)) == 32:
            return Fernet(key)
    except Exception:  # noqa: BLE001 - not a Fernet key; derive one below
        pass
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(derived)


def encrypt_credentials(credentials: Dict[str, Any]) -> str:
    """Serialise and encrypt a credentials mapping for storage in Redis."""
    payload = json.dumps(credentials).encode()
    return _fernet().encrypt(payload).decode()


def decrypt_credentials(blob: str) -> Dict[str, Any]:
    """Decrypt and deserialise what encrypt_credentials produced."""
    if isinstance(blob, bytes):
        blob = blob.decode()
    try:
        plaintext = _fernet().decrypt(blob.encode())
    except InvalidToken as exc:
        raise CredentialEncryptionError(
            "Stored credentials could not be decrypted. The credential key has "
            "changed, or the record was written by a different deployment."
        ) from exc
    return json.loads(plaintext)

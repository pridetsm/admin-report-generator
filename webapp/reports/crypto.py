"""Symmetric encryption for secrets stored in the DB (e.g. GrafanaConfigRevision's SMTP
password). The key is DERIVED from Django's own SECRET_KEY rather than a separate secret,
so there's nothing new to deploy, rotate or lose track of — rotating SECRET_KEY rotates this
too (and invalidates anything already encrypted, same as it already invalidates sessions)."""
import base64
import hashlib

from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken


def _fernet() -> Fernet:
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(plaintext: str) -> str:
    """'' in -> '' out (an unset secret stays unset, never becomes a ciphertext of '')."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """'' in -> '' out. A ciphertext that fails to decrypt (e.g. SECRET_KEY rotated since it
    was written) returns '' rather than raising — callers treat that the same as unset."""
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ""

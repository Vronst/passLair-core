"""
Single place that wraps passlair_crypto's derive_keys, plus DEK wrapping built
on top of core.crypto's generic AEAD encrypt/decrypt.

UserManager (login), UserWriter (registration, password changes), and
compare_passwords all need the same "derive a KEK from a password+salt, then
wrap/unwrap the DEK with it" steps. Keeping that composition here means the
call sites can't drift out of sync with each other if the underlying
KDF/AEAD scheme changes.
"""

import secrets

from passlair_crypto.package import derive_keys

from ..crypto import decrypt, encrypt
from .mnemonic import kek_to_phrase, phrase_to_kek

DEK_SIZE = 32
SALT_SIZE = 16


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def new_dek() -> bytes:
    return secrets.token_bytes(DEK_SIZE)


def new_backup_kek() -> tuple[bytes, str]:
    """
    Generates a random backup KEK, unrelated to any password. Never stored -
    returns both the raw key (to wrap the DEK with) and its 24-word recovery
    phrase (to show the user exactly once).
    """
    kek = secrets.token_bytes(DEK_SIZE)
    return kek, kek_to_phrase(kek)


def backup_kek_from_phrase(phrase: str) -> bytes:
    """Parses a recovery phrase back into its raw backup KEK."""
    return phrase_to_kek(phrase)


def hash_password(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """Derives (password_hash, kek) from a password+salt pair."""
    return derive_keys(password.encode("utf-8"), salt)


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bytes | None:
    """Returns the derived KEK if password matches expected_hash, else None."""
    password_hash, kek = hash_password(password, salt)
    if password_hash != expected_hash:
        return None
    return kek


def wrap_dek(dek: bytes, kek: bytes) -> tuple[bytes, bytes]:
    """Encrypts dek under kek with a fresh nonce. Returns (encrypted_dek, nonce)."""
    return encrypt(dek, kek)


def unwrap_dek(encrypted_dek: bytes, nonce: bytes, kek: bytes) -> bytes:
    return decrypt(encrypted_dek, nonce, kek)

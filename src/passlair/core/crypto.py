"""
Thin, generic wrapper around passlair_crypto's AEAD encrypt/decrypt calls.

This is the only place in the codebase that calls passlair_crypto's
encrypt_password/decrypt_password directly. Both credential/DEK wrapping
(core.auth.credentials) and vault-secret encryption (PasswordWriter/
PasswordReader) build on these two functions instead of generating their
own nonces and calling passlair_crypto separately.
"""

import os

from passlair_crypto.package import decrypt_password, encrypt_password

NONCE_SIZE = 12


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypts plaintext under key with a fresh nonce. Returns (ciphertext, nonce)."""
    nonce = os.urandom(NONCE_SIZE)
    return encrypt_password(plaintext, nonce, key), nonce


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    return decrypt_password(ciphertext, nonce, key)

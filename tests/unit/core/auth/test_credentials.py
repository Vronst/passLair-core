from passlair.core.auth.credentials import (
    hash_new_password,
    new_dek,
    unwrap_dek,
    verify_password,
    wrap_dek,
)
from passlair.core.crypto import NONCE_SIZE


class TestPositive:
    def test_hash_new_password_and_new_dek_return_distinct_bytes(self):
        salt1, _, _ = hash_new_password("hunter2")
        salt2, _, _ = hash_new_password("hunter2")
        assert salt1 != salt2
        assert new_dek() != new_dek()

    def test_hash_new_password_returns_salt_hash_and_kek(self):
        salt, password_hash, kek = hash_new_password("hunter2")

        assert isinstance(salt, bytes)
        assert isinstance(password_hash, bytes)
        assert isinstance(kek, bytes)

    def test_verify_password_succeeds_against_its_own_hash(self):
        salt, password_hash, _ = hash_new_password("hunter2")

        assert verify_password("hunter2", salt, password_hash) is not None

    def test_wrap_dek_produces_a_fresh_nonce_and_bytes_ciphertext(self):
        _, _, kek = hash_new_password("hunter2")
        dek = new_dek()

        encrypted_dek, nonce = wrap_dek(dek, kek)

        assert isinstance(encrypted_dek, bytes)
        assert len(nonce) == NONCE_SIZE
        assert encrypted_dek != dek

    def test_unwrap_dek_calls_through_to_decrypt_password(self):
        # decrypt_password is real AEAD decryption now, so proving the
        # plumbing is correct means round-tripping through wrap_dek first --
        # arbitrary ciphertext/nonce/kek would fail the auth tag check.
        _, _, kek = hash_new_password("hunter2")
        dek = new_dek()
        encrypted_dek, nonce = wrap_dek(dek, kek)

        assert unwrap_dek(encrypted_dek, nonce, kek) == dek


class TestNegative:
    def test_verify_password_fails_against_a_foreign_hash(self):
        salt, _, _ = hash_new_password("hunter2")

        assert verify_password("hunter2", salt, b"not-a-real-hash") is None

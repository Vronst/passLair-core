from passlair.core.auth.credentials import (
    hash_password,
    new_dek,
    new_salt,
    unwrap_dek,
    verify_password,
    wrap_dek,
)
from passlair.core.crypto import NONCE_SIZE


class TestPositive:
    def test_new_salt_and_new_dek_return_distinct_bytes(self):
        assert new_salt() != new_salt()
        assert new_dek() != new_dek()

    def test_hash_password_returns_hash_and_kek(self):
        password_hash, kek = hash_password("hunter2", new_salt())

        assert isinstance(password_hash, bytes)
        assert isinstance(kek, bytes)

    def test_verify_password_succeeds_against_its_own_hash(self):
        salt = new_salt()
        password_hash, _ = hash_password("hunter2", salt)

        assert verify_password("hunter2", salt, password_hash) is not None

    def test_wrap_dek_produces_a_fresh_nonce_and_bytes_ciphertext(self):
        salt = new_salt()
        _, kek = hash_password("hunter2", salt)
        dek = new_dek()

        encrypted_dek, nonce = wrap_dek(dek, kek)

        assert isinstance(encrypted_dek, bytes)
        assert len(nonce) == NONCE_SIZE
        assert encrypted_dek != dek

    def test_unwrap_dek_calls_through_to_decrypt_password(self):
        # passlair_crypto's decrypt_password is currently a passthrough mock
        # (doesn't actually reverse encrypt_password), so this only proves
        # the plumbing is correct, not real decryption round-tripping.
        salt = new_salt()
        _, kek = hash_password("hunter2", salt)

        assert (
            unwrap_dek(b"some-ciphertext", new_salt()[:NONCE_SIZE], kek)
            == b"some-ciphertext"
        )


class TestNegative:
    def test_verify_password_fails_against_a_foreign_hash(self):
        salt = new_salt()

        assert verify_password("hunter2", salt, b"not-a-real-hash") is None

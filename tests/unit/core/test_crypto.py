from passlair.core.crypto import NONCE_SIZE, decrypt, encrypt


class TestPositive:
    def test_encrypt_returns_ciphertext_and_fresh_nonce(self):
        ciphertext, nonce = encrypt(b"a secret", b"a_key")

        assert isinstance(ciphertext, bytes)
        assert isinstance(nonce, bytes)
        assert len(nonce) == NONCE_SIZE
        assert ciphertext != b"a secret"

    def test_encrypt_uses_a_different_nonce_each_call(self):
        _, nonce_one = encrypt(b"a secret", b"a_key")
        _, nonce_two = encrypt(b"a secret", b"a_key")

        assert nonce_one != nonce_two

    def test_decrypt_calls_through_to_decrypt_password(self):
        # passlair_crypto's decrypt_password is currently a passthrough mock
        # (doesn't actually reverse encrypt_password), so this only proves
        # the plumbing is correct, not real decryption round-tripping.
        assert decrypt(b"some-ciphertext", b"a_nonce", b"a_key") == b"some-ciphertext"

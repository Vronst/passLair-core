from passlair.core.crypto import NONCE_SIZE, decrypt, encrypt

KEY = b"k" * 32  # ChaCha20-Poly1305 requires an exact 32-byte key


class TestPositive:
    def test_encrypt_returns_ciphertext_and_fresh_nonce(self):
        ciphertext, nonce = encrypt(b"a secret", KEY)

        assert isinstance(ciphertext, bytes)
        assert isinstance(nonce, bytes)
        assert len(nonce) == NONCE_SIZE
        assert ciphertext != b"a secret"

    def test_encrypt_uses_a_different_nonce_each_call(self):
        _, nonce_one = encrypt(b"a secret", KEY)
        _, nonce_two = encrypt(b"a secret", KEY)

        assert nonce_one != nonce_two

    def test_decrypt_calls_through_to_decrypt_password(self):
        # decrypt_password is real AEAD decryption now, so proving the
        # plumbing is correct means round-tripping through encrypt first --
        # arbitrary ciphertext/nonce/key would fail the auth tag check.
        ciphertext, nonce = encrypt(b"a secret", KEY)

        assert decrypt(ciphertext, nonce, KEY) == b"a secret"

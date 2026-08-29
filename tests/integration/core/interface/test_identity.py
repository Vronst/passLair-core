from passlair.core.interface.identity import Identity
from passlair.core.readers.user_reader import UserReader


class TestPositive:
    def test_login_and_logout(self, register_user: dict[str, str]):
        tested = Identity()

        test_result = tested.login(register_user["username"], register_user["password"])
        assert test_result.success
        assert "user_id" in tested.login_status.data

        test_result = tested.logout()
        assert test_result.success
        assert "user_id" not in tested.login_status.data

    def test_change_user_password(self, register_user: dict[str, str]):
        tested = Identity()
        new_password = "new_test_password"

        assert tested.login(
            register_user["username"], register_user["password"]
        ).success

        before = UserReader.get_user_by_name(register_user["username"])

        assert tested.change_user_password(
            new_password, register_user["password"]
        ).success

        # passlair_crypto's derive_keys is currently a mock that ignores its
        # inputs, so a changed password can't be proven to invalidate the old
        # one yet; salt/dek_nonce being freshly re-randomized on every change
        # is the part of this flow real crypto doesn't affect.
        after = UserReader.get_user_by_name(register_user["username"])
        assert after is not None
        assert before is not None
        assert after.salt != before.salt
        assert after.dek_nonce != before.dek_nonce

        assert tested.logout().success
        assert tested.login(register_user["username"], new_password).success

    def test_register_and_loggin_status_after(self):
        """
        Tests if user is able to be registered, and if the user is logged right after registration.
        """
        tested = Identity()
        test_result = tested.register_user(
            "brand_new_user", "brand_new_user@example.com", "test_password"
        )

        assert test_result.success
        assert tested.login_status.success

    def test_password_reset(self, register_user: dict[str, str]):
        tested = Identity()
        new_password = "recovered_password"

        before = UserReader.get_user_by_name(register_user["username"])

        result = tested.reset_user_password(
            register_user["username"], register_user["backup_phrase"], new_password
        )
        assert result.success
        new_backup_phrase = result.data["backup_phrase"]
        assert isinstance(new_backup_phrase, str)
        assert len(new_backup_phrase.split()) == 24
        assert new_backup_phrase != register_user["backup_phrase"]

        # passlair_crypto's derive_keys/encrypt_password are currently mocks
        # that ignore their key/nonce inputs (see test_change_user_password),
        # so ciphertext alone can't prove anything rotated; the nonces being
        # freshly re-randomized on every reset is what real crypto doesn't
        # affect.
        after = UserReader.get_user_by_name(register_user["username"])
        assert after is not None
        assert before is not None
        assert after.salt != before.salt
        assert after.dek_nonce != before.dek_nonce
        assert after.backup_dek_nonce != before.backup_dek_nonce

        assert tested.login(register_user["username"], new_password).success

    def test_password_reset_wrong_phrase_rejected(self, register_user: dict[str, str]):
        tested = Identity()

        result = tested.reset_user_password(
            register_user["username"], "definitely not the right phrase", "new_password"
        )

        assert not result.success


class TestNegative:
    def test_change_user_password_when_not_logged_in(self):
        tested = Identity()

        test_result = tested.change_user_password("new_password", "old_password")

        assert not test_result.success
        assert "not logged in" in test_result.message.lower()

    def test_register_user_with_duplicate_username(self, register_user: dict[str, str]):
        tested = Identity()

        test_result = tested.register_user(
            register_user["username"], "someone_else@example.com", "another_password"
        )

        assert not test_result.success
        assert "username already exists" in test_result.message.lower()

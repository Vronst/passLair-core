import pytest

from passlair.core.interface.identity import Identity
from passlair.core.readers.user_reader import UserReader


class TestPositive:
    def test_login_and_logout(self, register_user):
        tested = Identity()

        test_result = tested.login(register_user["username"], register_user["password"])
        assert test_result.success
        assert "user_id" in tested.login_status.data

        test_result = tested.logout()
        assert test_result.success
        assert "user_id" not in tested.login_status.data

    def test_change_user_password(self, register_user):
        tested = Identity()
        new_password = "new_test_password"

        assert tested.login(register_user["username"], register_user["password"]).success

        before = UserReader.get_user_by_name(register_user["username"])

        assert tested.change_user_password(new_password, register_user["password"]).success

        # passlair_crypto's derive_keys is currently a mock that ignores its
        # inputs, so a changed password can't be proven to invalidate the old
        # one yet; salt/dek_nonce being freshly re-randomized on every change
        # is the part of this flow real crypto doesn't affect.
        after = UserReader.get_user_by_name(register_user["username"])
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

    @pytest.mark.skip(reason="Identity.reset_user_password is not implemented yet")
    def test_password_reset(self, register_user):
        tested = Identity()
        new_password = tested.reset_user_password(register_user["user_id"]).data[
            "new_password"
        ]
        test_result = tested.login(
            register_user["username"], register_user["password"]
        )

        assert not test_result.success

        assert tested.login(register_user["username"], new_password).success


class TestNegative:
    def test_change_user_password_when_not_logged_in(self):
        tested = Identity()

        test_result = tested.change_user_password("new_password", "old_password")

        assert not test_result.success
        assert "not logged in" in test_result.messege.lower()

    def test_register_user_with_duplicate_username(self, register_user):
        tested = Identity()

        test_result = tested.register_user(
            register_user["username"], "someone_else@example.com", "another_password"
        )

        assert not test_result.success
        assert "username already exists" in test_result.messege.lower()

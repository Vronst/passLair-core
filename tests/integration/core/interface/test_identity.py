import pytest

from passlair.core.interface.identity import Identity

login = {"username": "test_user", "password": "test_password"}
register = login.copy()
register['email'] = "test_email@example.com"
change_password = {
    "new_password": "new_test_password",
    "old_password": login["password"],
}


class TestPositive:
    def test_login_and_logout(self):
        tested = Identity()
        test_result = tested.login(**login)
        assert test_result["success"]
        assert "user_id" in tested.login_status["data"]

        test_result = tested.logout()
        assert test_result["success"]
        assert "user_id" not in tested.login_status["data"]

    def test_change_user_password(self):
        tested = Identity()
        test_result = tested.login(**login)
        assert test_result

        test_result = tested.change_user_password(**change_password)
        assert test_result

        test_result = tested.logout()
        assert test_result

        test_result = tested.login(**login)
        assert not test_result

        test_result = tested.login(login["username"], change_password["new_password"])
        assert test_result

    def test_register_and_loggin_status_after(self):
        """
        Tests if user is able to be registered, and if the user is logged right after registration.
        """
        tested = Identity()
        test_result = tested.register_user(register["username"], register['email'], register["password"])

        assert test_result.success
        assert tested.login_status

    def test_password_reset(self, register_user):
        tested = Identity()
        new_password = tested.reset_user_password(register_user["user_id"]).data[
            "new_password"
        ]
        test_result = tested.login(
            register_user["username"], register_user["master_password"]
        )

        assert not test_result.success

        assert tested.login(register_user["username"], new_password).success


class TestNegative:
    def test_change_user_password(self):
        tested = Identity()
        test_result = tested.change_user_password(**change_password)
        assert not test_result["success"]
        assert "Permission error" in test_result["data"]

    def test_register_user(self, register_user):
        tested = Identity()
        tested_result = tested.register_user(
            register_user["username"], register_user["email"], register_user["master_password"]
        )

        assert not tested_result.success

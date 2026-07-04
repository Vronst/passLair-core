import pytest

from passlair.core.interface.auth import Authentication

login = {"username": "test_user", "password": "test_password"}
change_password = {
    "new_password": "new_test_password",
    "old_password": login["password"],
}


class TestPositive:
    def test_login_and_logout(self):
        tested = Authentication()
        test_result = tested.login(**login)
        assert test_result["success"]
        assert "user_id" in tested.login_status["data"]

        test_result = tested.logout()
        assert test_result["success"]
        assert "user_id" not in tested.login_status["data"]

    def test_change_user_password(self):
        tested = Authentication()
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
        tested = Authentication()
        test_result = tested.register_user(login["username"], login["password"])

        assert test_result.success
        assert tested.login_status

    def test_password_reset(self, register_user):
        tested = Authentication()
        new_password = tested.reset_user_password(register_user["user_id"]).data[
            "new_password"
        ]
        test_result = tested.login(
            register_user["master_username"], register_user["master_password_hash"]
        )

        assert not test_result.success

        assert tested.login(register_user["master_username"], new_password).success


class TestNegative:
    def test_change_user_password(self):
        tested = Authentication()
        test_result = tested.change_user_password(**change_password)
        assert not test_result["success"]
        assert "Permission error" in test_result["data"]

    def test_register_user(self, register_user):
        tested = Authentication()
        tested_result = tested.register_user(
            register_user["master_username"], register_user["master_password_hash"]
        )

        assert not tested_result.success

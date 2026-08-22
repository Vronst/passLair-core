from unittest.mock import MagicMock, patch

from passlair.core.interface.identity import Identity


def make_identity(**overrides: MagicMock) -> tuple[Identity, MagicMock, MagicMock]:
    manager = overrides.get("manager", MagicMock())
    user_writer = overrides.get("user_writer", MagicMock())
    return Identity(user_manager=manager, user_writer=user_writer), manager, user_writer


class TestLoginStatus:
    def test_true_when_logged_in(self):
        identity, manager, _ = make_identity()
        manager.login_status = True
        manager.user_id = "user-1"

        result = identity.login_status

        assert result.success
        assert result.data == {"user_id": "user-1"}

    def test_false_when_not_logged_in(self):
        identity, manager, _ = make_identity()
        manager.login_status = False

        result = identity.login_status

        assert not result.success


class TestLogin:
    def test_success(self):
        identity, manager, _ = make_identity()
        manager.login.return_value = True

        result = identity.login("user", "password")

        assert result.success
        manager.login.assert_called_once_with("user", "password")

    def test_wrong_credentials(self):
        identity, manager, _ = make_identity()
        manager.login.return_value = False

        result = identity.login("user", "wrong_password")

        assert not result.success

    def test_already_logged_in_reports_failure_instead_of_raising(self):
        identity, manager, _ = make_identity()
        manager.login.side_effect = RuntimeError("User already logged in!")

        result = identity.login("user", "password")

        assert not result.success
        assert "already logged in" in result.messege


class TestLogout:
    def test_success(self):
        identity, manager, _ = make_identity()

        result = identity.logout()

        assert result.success
        manager.logout.assert_called_once()

    def test_not_logged_in_reports_failure_instead_of_raising(self):
        identity, manager, _ = make_identity()
        manager.logout.side_effect = RuntimeError("Tried login out when not loged.")

        result = identity.logout()

        assert not result.success


class TestChangeUserPassword:
    def test_old_password_required(self):
        identity, _, user_writer = make_identity()

        result = identity.change_user_password("new_password", None)

        assert not result.success
        user_writer.change_password.assert_not_called()

    def test_fails_when_not_logged_in(self):
        identity, manager, user_writer = make_identity()
        manager.login_status = False

        result = identity.change_user_password("new_password", "old_password")

        assert not result.success
        user_writer.change_password.assert_not_called()

    def test_fails_on_wrong_old_password(self):
        identity, manager, user_writer = make_identity()
        manager.login_status = True
        manager.user_id = "user-1"

        with patch(
            "passlair.core.interface.identity.compare_passwords", return_value=False
        ) as compare:
            result = identity.change_user_password("new_password", "wrong_old_password")

        assert not result.success
        compare.assert_called_once_with("user-1", "wrong_old_password")
        user_writer.change_password.assert_not_called()

    def test_success(self):
        identity, manager, user_writer = make_identity()
        manager.login_status = True
        manager.user_id = "user-1"

        with patch(
            "passlair.core.interface.identity.compare_passwords", return_value=True
        ):
            result = identity.change_user_password("new_password", "old_password")

        assert result.success
        user_writer.change_password.assert_called_once_with(
            "new_password", "old_password"
        )


class TestRegisterUser:
    def test_success(self):
        identity, manager, user_writer = make_identity()
        prepared = object()
        user_writer.prepare_new_user.return_value = (prepared, "word " * 23 + "word")

        result = identity.register_user("login", "email@example.com", "password")

        assert result.success
        assert result.data["backup_phrase"] == "word " * 23 + "word"
        user_writer.prepare_new_user.assert_called_once_with(
            "login", "email@example.com", "password"
        )
        user_writer.save_user.assert_called_once_with(prepared)
        manager.login.assert_called_once_with("login", "password")

    def test_failure_on_duplicate(self):
        identity, manager, user_writer = make_identity()
        user_writer.prepare_new_user.return_value = (object(), "irrelevant phrase")
        user_writer.save_user.side_effect = ValueError("Username already exists")

        result = identity.register_user("login", "email@example.com", "password")

        assert not result.success
        assert "Username already exists" in result.messege
        manager.login.assert_not_called()


class TestResetUserPassword:
    def test_success(self):
        identity, _, user_writer = make_identity()
        user_writer.reset_password.return_value = "new backup phrase"

        result = identity.reset_user_password(
            "bob", "old backup phrase", "new_password"
        )

        assert result.success
        assert result.data["backup_phrase"] == "new backup phrase"
        user_writer.reset_password.assert_called_once_with(
            "bob", "new_password", "old backup phrase"
        )

    def test_failure_bubbles_up_as_result(self):
        identity, _, user_writer = make_identity()
        user_writer.reset_password.side_effect = ValueError("User doesn't exists!")

        result = identity.reset_user_password(
            "bob", "old backup phrase", "new_password"
        )

        assert not result.success
        assert "User doesn't exists" in result.messege

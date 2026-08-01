from unittest.mock import MagicMock

import pytest

from passlair.core.interface.password_manager import PasswordManager


def make_password_manager(mock_user_manager):
    manager = PasswordManager(mock_user_manager)
    manager.pass_reader = MagicMock()
    manager.pass_writer = MagicMock()
    return manager


class TestInit:
    def test_wraps_reader_and_writer_for_given_user(self, mock_user_manager):
        manager = PasswordManager(mock_user_manager)

        assert manager.auth is mock_user_manager
        assert manager.pass_reader.user is mock_user_manager
        assert manager.pass_writer.user is mock_user_manager


class TestGetPasswordForService:
    def test_success(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_reader.get_pass_for.return_value = {  # pyright: ignore[reportAttributeAccessIssue]
            "login": "bob",
            "password": "hunter2",
        }

        result = manager.get_password_for_service("github.com")

        assert result.success
        assert result.data == {"login": "bob", "password": "hunter2"}
        manager.pass_reader.get_pass_for.assert_called_once_with("github.com")  # pyright: ignore[reportAttributeAccessIssue]

    def test_not_found_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_reader.get_pass_for.side_effect = KeyError(  # pyright: ignore[reportAttributeAccessIssue]
            "Password for this service not found"
        )

        result = manager.get_password_for_service("github.com")

        assert not result.success
        assert "not found" in result.messege

    def test_no_active_session_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_reader.get_pass_for.side_effect = PermissionError(  # pyright: ignore[reportAttributeAccessIssue]
            "No active secure session. Please log in."
        )

        result = manager.get_password_for_service("github.com")

        assert not result.success
        assert "log in" in result.messege

    def test_unhandled_exception_propagates(self, mock_user_manager):
        """Regression guard: only KeyError/RuntimeError/PermissionError are meant to be caught."""
        manager = make_password_manager(mock_user_manager)
        manager.pass_reader.get_pass_for.side_effect = ValueError("unexpected")  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(ValueError):
            manager.get_password_for_service("github.com")


class TestSetPasswordForService:
    def test_success(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.return_value = True  # pyright: ignore[reportAttributeAccessIssue]

        result = manager.set_password_for_service("github.com", "bob", "hunter2")

        assert result.success
        manager.pass_writer.save_password.assert_called_once_with(  # pyright: ignore[reportAttributeAccessIssue]
            "github.com", "bob", "hunter2"
        )

    def test_save_returning_false_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.return_value = False  # pyright: ignore[reportAttributeAccessIssue]

        result = manager.set_password_for_service("github.com", "bob", "hunter2")

        assert not result.success
        assert "Failed to save credentials" in result.messege

    def test_validation_error_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.side_effect = ValueError(  # pyright: ignore[reportAttributeAccessIssue]
            "Service name, login and password must not be empty"
        )

        result = manager.set_password_for_service("", "bob", "hunter2")

        assert not result.success
        assert "must not be empty" in result.messege

    def test_type_error_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.side_effect = TypeError("bad argument type")  # pyright: ignore[reportAttributeAccessIssue]

        result = manager.set_password_for_service("github.com", "bob", "hunter2")

        assert not result.success
        assert "bad argument type" in result.messege

    def test_no_active_session_reports_failure(self, mock_user_manager):
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.side_effect = PermissionError(  # pyright: ignore[reportAttributeAccessIssue]
            "No active secure session. Please log in."
        )

        result = manager.set_password_for_service("github.com", "bob", "hunter2")

        assert not result.success
        assert "log in" in result.messege

    def test_unhandled_exception_propagates(self, mock_user_manager):
        """Regression guard: the except tuple shouldn't silently widen to catch everything."""
        manager = make_password_manager(mock_user_manager)
        manager.pass_writer.save_password.side_effect = ArithmeticError("unexpected")  # pyright: ignore[reportAttributeAccessIssue]

        with pytest.raises(ArithmeticError):
            manager.set_password_for_service("github.com", "bob", "hunter2")

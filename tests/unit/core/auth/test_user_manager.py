from unittest.mock import patch

import pytest

from passlair.core.auth.user_manager import UserManager
from passlair.core.readers.user_reader import UserReader

username = "some_name"
password = "some_password"
dek = "some_dek"


class TestPositive:
    def test_init(self):
        manager = UserManager()

        assert manager.user_id is None

    def test_user_login(self, mock_user):
        manager = UserManager()
        with patch.object(
            UserManager, "_verify_password", return_value=(mock_user, b"some_kek")
        ) as mock:
            test_data = manager.login(username, password)

        assert test_data
        mock.assert_called_once_with(username, password)

    def test_user_login_wrong_password(self, mock_user):
        manager = UserManager()
        with patch.object(UserManager, "_verify_password", return_value=None) as mock:
            test_data = manager.login(username, password)

        assert not test_data
        mock.assert_called_once_with(username, password)

    def test_logout(self):
        manager = UserManager()
        manager._UserManager__dek = "some_dek"  # pyright: ignore[reportAttributeAccessIssue]
        manager._UserManager__user_id = "some_id"  # pyright: ignore[reportAttributeAccessIssue]
        manager.logout()

        assert manager.user_id is None
        # Regression guard: logout must actually clear the DEK, not just the
        # user_id, or a decrypted session key stays usable after "logging out".
        with pytest.raises(PermissionError):
            manager.get_session_key()

    def test_login_status_true_when_dek_and_user_id_set(self):
        manager = UserManager()
        manager._UserManager__dek = "some_dek"  # pyright: ignore[reportAttributeAccessIssue]
        manager._UserManager__user_id = "some_id"  # pyright: ignore[reportAttributeAccessIssue]

        assert manager.login_status is True

    def test_login_status_false_when_not_logged_in(self):
        manager = UserManager()

        assert manager.login_status is False

    def test_get_session_key(self):
        manager = UserManager()
        manager._UserManager__dek = dek  # pyright: ignore[reportAttributeAccessIssue]
        test_data = manager.get_session_key()

        assert test_data == dek

    def test_verify_password(self, mock_user):
        manager = UserManager()
        with patch.object(
            UserReader, "get_user_by_name", return_value=mock_user
        ) as mock:
            test_data = manager._verify_password(username, password)

        assert test_data
        user, kek = test_data
        assert user.salt == b"salt"
        mock.assert_called_once_with(username)


class TestNegative:
    def test_assign_user_id_manually(self):
        manager = UserManager()
        with pytest.raises(AttributeError):
            manager.user_id = "some id that is string"  # pyright: ignore[reportAttributeAccessIssue]

    def test_not_initialized_session(self):
        manager = UserManager()
        with pytest.raises(PermissionError):
            manager.get_session_key()

    def test_login_no_user(self):
        manager = UserManager()
        manager._UserManager__user_id = "some_id"  # pyright: ignore[reportAttributeAccessIssue]
        with pytest.raises(RuntimeError):
            manager.login("some_name", "some_password")

    def test_logout_not_loged(self):
        manager = UserManager()
        with pytest.raises(RuntimeError):
            manager.logout()

    def test_get_session_key_not_loged(self):
        manager = UserManager()
        with pytest.raises(PermissionError):
            manager.get_session_key()

    def test_verify_password_incorrect(self, mock_user):
        manager = UserManager()
        with patch.object(UserReader, "get_user_by_name", return_value=None):
            test_data = manager._verify_password(username, password)

        assert test_data is None

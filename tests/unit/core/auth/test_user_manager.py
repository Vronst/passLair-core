from unittest.mock import MagicMock, patch

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

    def test_user_login(self, mock_user: MagicMock):
        manager = UserManager()
        kek = b"some_kek"

        # Unit test of login()'s own wiring: _verify_password is already
        # mocked out, and unwrap_dek (real AEAD decryption) is mocked too so
        # this doesn't depend on the crypto backend at all -- that's covered
        # by test_credentials.py and by the real login in test_identity.py.
        with (
            patch.object(
                UserManager, "_verify_password", return_value=(mock_user, kek)
            ) as mock_verify,
            patch(
                "passlair.core.auth.user_manager.unwrap_dek", return_value=b"some_dek"
            ) as mock_unwrap,
        ):
            test_data = manager.login(username, password)

        assert test_data
        mock_verify.assert_called_once_with(username, password)
        mock_unwrap.assert_called_once_with(mock_user.dek, mock_user.dek_nonce, kek)

    def test_user_login_wrong_password(self, mock_user: MagicMock):
        manager = UserManager()
        with patch.object(UserManager, "_verify_password", return_value=None) as mock:
            test_data = manager.login(username, password)

        assert not test_data
        mock.assert_called_once_with(username, password)

    def test_logout(self):
        manager = UserManager()
        manager._UserManager__dek = "some_dek"
        manager._UserManager__user_id = "some_id"
        manager.logout()

        assert manager.user_id is None
        # Regression guard: logout must actually clear the DEK, not just the
        # user_id, or a decrypted session key stays usable after "logging out".
        with pytest.raises(PermissionError):
            _ = manager.get_session_key()

    def test_login_status_true_when_dek_and_user_id_set(self):
        manager = UserManager()
        manager._UserManager__dek = "some_dek"
        manager._UserManager__user_id = "some_id"

        assert manager.login_status is True

    def test_login_status_false_when_not_logged_in(self):
        manager = UserManager()

        assert manager.login_status is False

    def test_get_session_key(self):
        manager = UserManager()
        manager._UserManager__dek = dek
        test_data = manager.get_session_key()

        assert test_data == dek

    def test_verify_password(self, mock_user: MagicMock):
        manager = UserManager()
        # Unit test of _verify_password()'s own wiring: mock verify_password
        # (the credentials-module boundary) rather than depending on real
        # Argon2 succeeding -- that's covered by test_credentials.py.
        with (
            patch.object(
                UserReader, "get_user_by_name", return_value=mock_user
            ) as mock_reader,
            patch(
                "passlair.core.auth.user_manager.verify_password",
                return_value=b"some_kek",
            ) as mock_verify,
        ):
            test_data = manager._verify_password(username, password)

        assert test_data == (mock_user, b"some_kek")
        mock_reader.assert_called_once_with(username)
        mock_verify.assert_called_once_with(
            password, mock_user.salt, mock_user.master_password
        )


class TestNegative:
    def test_assign_user_id_manually(self):
        manager = UserManager()
        with pytest.raises(AttributeError):
            manager.user_id = "some id that is string"

    def test_not_initialized_session(self):
        manager = UserManager()
        with pytest.raises(PermissionError):
            _ = manager.get_session_key()

    def test_login_no_user(self):
        manager = UserManager()
        manager._UserManager__user_id = "some_id"
        with pytest.raises(RuntimeError):
            _ = manager.login("some_name", "some_password")

    def test_logout_not_loged(self):
        manager = UserManager()
        with pytest.raises(RuntimeError):
            manager.logout()

    def test_get_session_key_not_loged(self):
        manager = UserManager()
        with pytest.raises(PermissionError):
            _ = manager.get_session_key()

    def test_verify_password_incorrect(self, mock_user: MagicMock):
        manager = UserManager()
        with patch.object(UserReader, "get_user_by_name", return_value=None):
            test_data = manager._verify_password(username, password)

        assert test_data is None

from unittest.mock import MagicMock, patch
from passlair.core.readers.helpers import compare_passwords
from passlair.core.readers.user_reader import UserReader


class TestPositive:
    def test_compare_passwords(self, mock_user: MagicMock):
        # Unit test of compare_passwords()'s own wiring: mock verify_password
        # (the credentials-module boundary) rather than depending on real
        # Argon2 succeeding -- that's covered by test_credentials.py.
        with (
            patch.object(UserReader, "get_user_by", return_value=mock_user),
            patch(
                "passlair.core.readers.helpers.verify_password",
                return_value=b"some_kek",
            ) as mock_verify,
        ):
            assert compare_passwords(user_id="secret_id", password="some_password")

        mock_verify.assert_called_once_with(
            "some_password", mock_user.salt, mock_user.master_password
        )


class TestNegative:
    def test_compare_passwords_user_not_found(self):
        with patch.object(UserReader, "get_user_by", return_value=None):
            assert not compare_passwords(user_id="unknown_id", password="some_password")

    def test_compare_passwords_wrong_password(self, mock_user: MagicMock):
        with (
            patch.object(UserReader, "get_user_by", return_value=mock_user),
            patch("passlair.core.readers.helpers.verify_password", return_value=None),
        ):
            assert not compare_passwords(user_id="secret_id", password="wrong_password")

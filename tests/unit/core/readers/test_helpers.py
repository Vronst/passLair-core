from unittest.mock import MagicMock, patch
from passlair.core.readers.helpers import compare_passwords
from passlair.core.readers.user_reader import UserReader


class TestPositive:
    def test_compare_passwords(self, mock_user: MagicMock):

        with patch.object(UserReader, "get_user_by", return_value=mock_user):
            assert compare_passwords(user_id="secret_id", password="some_password")


class TestNegative:
    def test_compare_passwords_user_not_found(self):
        with patch.object(UserReader, "get_user_by", return_value=None):
            assert not compare_passwords(user_id="unknown_id", password="some_password")

    def test_compare_passwords_wrong_password(self, mock_user: MagicMock):
        mock_user.master_password = b"not-the-derived-hash"

        with patch.object(UserReader, "get_user_by", return_value=mock_user):
            assert not compare_passwords(user_id="secret_id", password="wrong_password")

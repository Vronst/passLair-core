from unittest.mock import patch

from passlair.core.models.standard_user import StandardUser
from passlair.core.readers.user_reader import UserReader

# get_user_by_name/get_user_by are classmethods, so calling them through the
# class (rather than an instance) is the only behavior worth covering here.


class TestPositive:
    def test_get_user_by_name(self, mock_user):
        with patch.object(UserReader, "_fetch_row", return_value=mock_user) as fetch:
            test_data = UserReader.get_user_by_name("name")

        assert test_data == mock_user
        fetch.assert_called_once_with(StandardUser, filters={"username": "name"})

    def test_get_user_by_name_not_exists(self):
        with patch.object(UserReader, "_fetch_row", return_value=None):
            test_data = UserReader.get_user_by_name("nothing there")

        assert test_data is None

    def test_get_user_by(self, mock_user):
        with patch.object(UserReader, "_fetch_row", return_value=mock_user) as fetch:
            test_data = UserReader.get_user_by(id="secret_id")

        assert test_data == mock_user
        fetch.assert_called_once_with(StandardUser, filters={"id": "secret_id"})

    def test_get_user_by_not_exists(self):
        with patch.object(UserReader, "_fetch_row", return_value=None):
            test_data = UserReader.get_user_by(id="unknown_id")

        assert test_data is None


class TestNegative:
    pass

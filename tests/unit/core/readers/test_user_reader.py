from unittest.mock import patch

from passlair.core.models.standard_user import StandardUser
from passlair.core.readers.user_reader import UserReader


class TestPositive:
    def test_get_user_by_name(self):
        reader = UserReader()
        with patch.object(UserReader, "_fetch_row", return_value="some user"):
            test_data = reader.get_user_by_name("name")

        assert test_data
        # assert isinstance(test_data, StandardUser) TODO

    def test_get_user_by_name_not_exists(self):
        reader = UserReader()
        with patch.object(UserReader, "_fetch_row", return_value=None):
            test_data = reader.get_user_by_name("nothing there")

        assert test_data is None
        # assert isinstance(test_data, StandardUser) TODO

    def test_get_user_by_name_classmethod(self):
        with patch.object(UserReader, "_fetch_row", return_value="some user"):
            test_data = UserReader.get_user_by_name("name")

        assert test_data
        # assert isinstance(test_data, StandardUser) TODO

    def test_get_user_by_name_not_exists_classmethod(self):
        with patch.object(UserReader, "_fetch_row", return_value=None):
            test_data = UserReader.get_user_by_name("nothing there")

        assert test_data is None
        # assert isinstance(test_data, StandardUser) TODO


class TestNegative:
    pass

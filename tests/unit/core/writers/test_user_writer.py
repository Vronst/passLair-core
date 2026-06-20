from unittest.mock import MagicMock, patch

import pytest

from passlair.core.models.standard_user import StandardUser
from passlair.core.writers.user_writer import UserWriter


class TestPositive:
    def test_save_user_successfully_inserts_record(
        self, mock_db_session, mock_user_data
    ):
        """Verify that a brand new user is accurately staged and saved to the DB."""
        mock_session, _ = mock_db_session

        # Patch the internal lookup to simulate that the username doesn't exist yet
        with patch.object(UserWriter, "_fetch_row", return_value=None) as mock_fetch:
            # Execute target method
            UserWriter.save_user(mock_user_data)

            # Assertions
            mock_fetch.assert_called_once_with(
                StandardUser, filters={"master_username": mock_user_data.username}
            )
            mock_session.add.assert_called_once()

            mock_session.commit.assert_called_once()

    def test_password_reset(self, mock_user_manager, mock_user_data):
        writer = UserWriter(mock_user_manager)


class TestNegative:
    def test_save_user_raises_exception_if_username_taken(
        self, mock_db_session, mock_user_data
    ):
        """Ensure we don't overwrite data if _fetch_row finds an existing user."""
        mock_session, _ = mock_db_session

        # Simulate finding an existing record in the DB
        existing_user_mock = MagicMock()
        with patch.object(UserWriter, "_fetch_row", return_value=existing_user_mock):
            # Assuming your code raises a ValueError or custom exception for duplicates
            with pytest.raises(ValueError, match="Username already exists"):
                UserWriter.save_user(mock_user_data)

            # Ensure database state wasn't mutated
            mock_session.add.assert_not_called()

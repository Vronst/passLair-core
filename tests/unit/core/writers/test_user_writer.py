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
        UserWriter.save_user(mock_user_data)

        mock_session.add.assert_called_once()

        mock_session.commit.assert_called_once()


class TestNegative:
    pass
    # FIXME: INTEGRATION REQURED
    # def test_save_user_raises_exception_if_username_taken(
    #     self, mock_db_session, mock_user_data
    # ):
    #     """Ensure we don't overwrite data if _fetch_row finds an existing user."""
    #     mock_session, _ = mock_db_session

    #     UserWriter.save_user(mock_user_data)
    #     # Simulate finding an existing record in the DB
    #     with pytest.raises(ValueError, match="Username already exists"):
    #         UserWriter.save_user(mock_user_data)

    #         # Ensure database state wasn't mutated
    #     mock_session.add.assert_not_called()

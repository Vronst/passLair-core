from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError

from passlair.core.models.standard_user import StandardUser
from passlair.core.writers.user_writer import UserWriter


class TestPositive:
    def test_save_user_successfully_inserts_record(
        self, mock_db_session, mock_user_data
    ):
        """Verify that a brand new user is accurately staged and saved to the DB."""
        mock_session, _ = mock_db_session

        UserWriter.save_user(mock_user_data)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_prepare_new_user(self):
        """Regression guard: must produce real bytes (not bytearray/str) for every field."""
        data = UserWriter.prepare_new_user("bob", "bob@example.com", "hunter2")

        assert data.username == "bob"
        assert data.email == "bob@example.com"
        assert isinstance(data.master_password, bytes)
        assert isinstance(data.salt, bytes)
        assert isinstance(data.dek, bytes)
        assert isinstance(data.dek_nonce, bytes)
        assert len(data.dek_nonce) == 12

    def test_change_password(self, mock_user, mock_user_manager, mock_db_session):
        mock_session, _ = mock_db_session
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=mock_user):
            writer.change_password("new_password", "old_password")

        mock_session.add.assert_called_once_with(mock_user)
        mock_session.commit.assert_called_once()


class TestNegative:
    def test_save_user_raises_on_duplicate_username(self, mock_db_session, mock_user_data):
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT", {}, Exception("UNIQUE constraint failed: standard_users.username")
        )

        with pytest.raises(ValueError, match="Username already exists"):
            UserWriter.save_user(mock_user_data)

    def test_save_user_raises_on_duplicate_email(self, mock_db_session, mock_user_data):
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT", {}, Exception("UNIQUE constraint failed: standard_users.email")
        )

        with pytest.raises(ValueError, match="Email already exists"):
            UserWriter.save_user(mock_user_data)

    def test_change_password_user_not_found(self, mock_user_manager):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=None):
            with pytest.raises(ValueError, match="User doesn't exists"):
                writer.change_password("new_password", "old_password")

    def test_change_password_wrong_old_password(self, mock_user, mock_user_manager):
        mock_user.master_password = b"not-the-derived-hash"
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=mock_user):
            with pytest.raises(ValueError, match="Old password incorrect"):
                writer.change_password("new_password", "old_password")

    def test_init_fails_with_invalid_user(self):
        """Regression guard: UserWriter must depend on AuthenticatedUser, not a concrete class."""
        with pytest.raises(TypeError):
            UserWriter(user=None)

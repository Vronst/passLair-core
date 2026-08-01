from unittest.mock import patch

import pytest
from sqlalchemy.exc import IntegrityError

from passlair.core.auth.credentials import backup_kek_from_phrase, new_dek, wrap_dek
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
        data, backup_phrase = UserWriter.prepare_new_user("bob", "bob@example.com", "hunter2")

        assert data.username == "bob"
        assert data.email == "bob@example.com"
        assert isinstance(data.master_password, bytes)
        assert isinstance(data.salt, bytes)
        assert isinstance(data.dek, bytes)
        assert isinstance(data.dek_nonce, bytes)
        assert len(data.dek_nonce) == 12
        assert isinstance(data.backup_dek, bytes)
        assert isinstance(data.backup_dek_nonce, bytes)
        assert len(data.backup_dek_nonce) == 12
        assert len(backup_phrase.split()) == 24

    def test_reset_password(self, mock_user, mock_user_manager, mock_db_session):
        mock_session, _ = mock_db_session
        _, backup_phrase = UserWriter.prepare_new_user("bob", "bob@example.com", "hunter2")

        # reset_password needs a user row whose backup_dek was actually
        # wrapped under the KEK that backup_phrase decodes to, so build one
        # from real prepare_new_user output rather than the generic mock_user.
        dek = new_dek()
        backup_dek, backup_dek_nonce = wrap_dek(dek, backup_kek_from_phrase(backup_phrase))
        mock_user.backup_dek = backup_dek
        mock_user.backup_dek_nonce = backup_dek_nonce

        writer = UserWriter(user=mock_user_manager)
        with patch.object(UserWriter, "_fetch_row", return_value=mock_user):
            new_phrase = writer.reset_password("bob", "new_password", backup_phrase)

        assert len(new_phrase.split()) == 24
        assert new_phrase != backup_phrase
        mock_session.add.assert_called_once_with(mock_user)
        mock_session.commit.assert_called_once()

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

    def test_reset_password_user_not_found(self, mock_user_manager):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=None):
            with pytest.raises(ValueError, match="User doesn't exists"):
                writer.reset_password("bob", "new_password", "irrelevant phrase")

    def test_reset_password_bad_phrase_rejected(self, mock_user, mock_user_manager):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=mock_user):
            with pytest.raises(ValueError, match="Backup phrase"):
                writer.reset_password("bob", "new_password", "not a valid phrase")

    def test_init_fails_with_invalid_user(self):
        """Regression guard: UserWriter must depend on AuthenticatedUser, not a concrete class."""
        with pytest.raises(TypeError):
            UserWriter(user=None)

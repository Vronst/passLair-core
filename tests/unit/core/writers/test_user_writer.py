from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError

from passlair.core.writers.user_writer import UserWriter
from passlair.dataclasses.user_data import UserCreation


class TestPositive:
    def test_save_user_successfully_inserts_record(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        """Verify that a brand new user is accurately staged and saved to the DB."""
        mock_session, _ = mock_db_session

        UserWriter.save_user(mock_user_data)

        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_prepare_new_user(self):
        """Regression guard: must produce real bytes (not bytearray/str) for every field."""
        data, backup_phrase = UserWriter.prepare_new_user(
            "bob", "bob@example.com", "hunter2"
        )

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

    def test_reset_password(
        self,
        mock_user: MagicMock,
        mock_user_manager: MagicMock,
        mock_db_session: tuple[MagicMock, MagicMock],
    ):
        mock_session, _ = mock_db_session
        writer = UserWriter(user=mock_user_manager)
        original_backup_dek = mock_user.backup_dek
        original_backup_dek_nonce = mock_user.backup_dek_nonce

        # Unit test of reset_password()'s own wiring: mock every
        # credentials-module boundary call rather than depending on real
        # crypto succeeding -- the real backup-phrase roundtrip is covered by
        # test_password_reset in the integration test_identity.py, and bad
        # phrases actually being rejected is covered by
        # test_reset_password_bad_phrase_rejected below (that one needs the
        # real mnemonic validation, so it's left alone).
        with (
            patch.object(UserWriter, "_fetch_row", return_value=mock_user),
            patch(
                "passlair.core.writers.user_writer.backup_kek_from_phrase",
                return_value=b"backup_kek",
            ) as mock_phrase_to_kek,
            patch(
                "passlair.core.writers.user_writer.unwrap_dek",
                return_value=b"plain_dek",
            ) as mock_unwrap,
            patch(
                "passlair.core.writers.user_writer.hash_new_password",
                return_value=(b"new_salt", b"new_hash", b"new_kek"),
            ) as mock_hash,
            patch(
                "passlair.core.writers.user_writer.new_backup_kek",
                return_value=(b"new_backup_kek", "new backup phrase"),
            ) as mock_new_backup_kek,
            patch(
                "passlair.core.writers.user_writer.wrap_dek",
                side_effect=[
                    (b"enc_dek", b"dek_nonce"),
                    (b"enc_backup_dek", b"backup_nonce"),
                ],
            ) as mock_wrap,
        ):
            new_phrase = writer.reset_password(
                "bob", "new_password", "old backup phrase"
            )

        assert new_phrase == "new backup phrase"
        mock_phrase_to_kek.assert_called_once_with("old backup phrase")
        mock_unwrap.assert_called_once_with(
            original_backup_dek, original_backup_dek_nonce, b"backup_kek"
        )
        mock_hash.assert_called_once_with("new_password")
        mock_new_backup_kek.assert_called_once()
        assert mock_wrap.call_args_list == [
            ((b"plain_dek", b"new_kek"),),
            ((b"plain_dek", b"new_backup_kek"),),
        ]
        assert mock_user.master_password == b"new_hash"
        assert mock_user.salt == b"new_salt"
        assert mock_user.dek == b"enc_dek"
        assert mock_user.dek_nonce == b"dek_nonce"
        assert mock_user.backup_dek == b"enc_backup_dek"
        assert mock_user.backup_dek_nonce == b"backup_nonce"
        mock_session.add.assert_called_once_with(mock_user)
        mock_session.commit.assert_called_once()

    def test_change_password(
        self,
        mock_user: MagicMock,
        mock_user_manager: MagicMock,
        mock_db_session: tuple[MagicMock, MagicMock],
    ):
        mock_session, _ = mock_db_session
        writer = UserWriter(user=mock_user_manager)
        # change_password mutates mock_user.salt/.master_password/.dek/.dek_nonce
        # in place, so capture the pre-call values now -- asserting against
        # mock_user.salt after the call would read the already-mutated value.
        original_salt = mock_user.salt
        original_master_password = mock_user.master_password
        original_dek = mock_user.dek
        original_dek_nonce = mock_user.dek_nonce

        # Unit test of change_password()'s own wiring: mock every
        # credentials-module boundary call rather than depending on real
        # crypto succeeding -- that's covered by test_credentials.py and by
        # the real change_password in test_identity.py.
        with (
            patch.object(UserWriter, "_fetch_row", return_value=mock_user),
            patch(
                "passlair.core.writers.user_writer.verify_password",
                return_value=b"old_kek",
            ) as mock_verify,
            patch(
                "passlair.core.writers.user_writer.unwrap_dek",
                return_value=b"plain_dek",
            ) as mock_unwrap,
            patch(
                "passlair.core.writers.user_writer.hash_new_password",
                return_value=(b"new_salt", b"new_hash", b"new_kek"),
            ) as mock_hash,
            patch(
                "passlair.core.writers.user_writer.wrap_dek",
                return_value=(b"enc_dek", b"new_nonce"),
            ) as mock_wrap,
        ):
            writer.change_password("new_password", "old_password")

        mock_verify.assert_called_once_with(
            "old_password", original_salt, original_master_password
        )
        mock_unwrap.assert_called_once_with(
            original_dek, original_dek_nonce, b"old_kek"
        )
        mock_hash.assert_called_once_with("new_password")
        mock_wrap.assert_called_once_with(b"plain_dek", b"new_kek")
        assert mock_user.master_password == b"new_hash"
        assert mock_user.salt == b"new_salt"
        assert mock_user.dek == b"enc_dek"
        assert mock_user.dek_nonce == b"new_nonce"
        mock_session.add.assert_called_once_with(mock_user)
        mock_session.commit.assert_called_once()


class TestNegative:
    def test_save_user_raises_on_duplicate_username(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT", {}, Exception("UNIQUE constraint failed: standard_users.username")
        )

        with pytest.raises(ValueError, match="Username already exists"):
            UserWriter.save_user(mock_user_data)

    def test_save_user_raises_on_duplicate_email(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT", {}, Exception("UNIQUE constraint failed: standard_users.email")
        )

        with pytest.raises(ValueError, match="Email already exists"):
            UserWriter.save_user(mock_user_data)

    def test_save_user_raises_on_duplicate_username_mysql_style(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        """pymysql reports duplicates as (1062, "Duplicate entry ... for key
        '...username'") -- the sqlite phrasing check must not be the only one."""
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT",
            {},
            Exception(1062, "Duplicate entry 'bob' for key 'standard_users.username'"),
        )

        with pytest.raises(ValueError, match="Username already exists"):
            UserWriter.save_user(mock_user_data)

    def test_save_user_uniqueness_violation_with_undetermined_column(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        """A genuine duplicate whose column can't be read off the message
        (e.g. MySQL 'for key PRIMARY') still reports a duplicate, generically."""
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT", {}, Exception(1062, "Duplicate entry '...' for key 'PRIMARY'")
        )

        with pytest.raises(ValueError, match="already exists"):
            UserWriter.save_user(mock_user_data)

    def test_save_user_does_not_mislabel_non_uniqueness_integrity_error(
        self,
        mock_db_session: tuple[MagicMock, MagicMock],
        mock_user_data: UserCreation,
    ):
        """A NOT NULL / FK violation is a bug, not a duplicate account -- it
        must not surface as 'already exists'."""
        mock_session, _ = mock_db_session
        mock_session.commit.side_effect = IntegrityError(
            "INSERT",
            {},
            Exception("NOT NULL constraint failed: standard_users.email"),
        )

        with pytest.raises(ValueError, match="database constraint") as excinfo:
            UserWriter.save_user(mock_user_data)

        assert "already exists" not in str(excinfo.value)

    def test_change_password_user_not_found(self, mock_user_manager: MagicMock):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=None):
            with pytest.raises(ValueError, match="User doesn't exists"):
                writer.change_password("new_password", "old_password")

    def test_change_password_wrong_old_password(
        self, mock_user: MagicMock, mock_user_manager: MagicMock
    ):
        writer = UserWriter(user=mock_user_manager)

        with (
            patch.object(UserWriter, "_fetch_row", return_value=mock_user),
            patch(
                "passlair.core.writers.user_writer.verify_password", return_value=None
            ),
        ):
            with pytest.raises(ValueError, match="Old password incorrect"):
                writer.change_password("new_password", "old_password")

    def test_reset_password_user_not_found(self, mock_user_manager: MagicMock):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=None):
            with pytest.raises(ValueError, match="User doesn't exists"):
                _ = writer.reset_password("bob", "new_password", "irrelevant phrase")

    def test_reset_password_bad_phrase_rejected(
        self, mock_user: MagicMock, mock_user_manager: MagicMock
    ):
        writer = UserWriter(user=mock_user_manager)

        with patch.object(UserWriter, "_fetch_row", return_value=mock_user):
            with pytest.raises(ValueError, match="Backup phrase"):
                _ = writer.reset_password("bob", "new_password", "not a valid phrase")

    def test_init_fails_with_invalid_user(self):
        """Regression guard: UserWriter must depend on AuthenticatedUser, not a concrete class."""
        with pytest.raises(TypeError):
            _ = UserWriter(user=None)

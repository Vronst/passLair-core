from unittest.mock import MagicMock, patch

import pytest

from passlair.core.models.vault_entry import VaultEntry
from passlair.core.readers.password_reader import PasswordReader

password = "retrievedPassword"
dek = b"dek"
data = {
    "service_name": "test_service",
    # "user_id ": "string_id",
    "login": "my_login",
    "password": b"encrypted_pass",
    "nonce": b"12",
}
entry = VaultEntry(**data)


class TestPositive:
    def test_init(self, mock_user_manager: MagicMock):
        reader = PasswordReader(mock_user_manager)
        assert reader.user == mock_user_manager

    def test_get_pass_for(self, mock_user_manager: MagicMock):
        reader = PasswordReader(mock_user_manager)
        with (
            patch.object(
                PasswordReader, "_retrieve_password", return_value=password
            ) as retriever,
            patch.object(
                PasswordReader, "_decrypt_password", return_value=password
            ) as decrypt,
        ):
            test_data = reader.get_pass_for(data["service_name"])

        assert test_data == password
        retriever.assert_called_once_with(data["service_name"])
        decrypt.assert_called_once_with(password, mock_user_manager.get_session_key())

    def test_decrypt_password(self, mock_user_manager: MagicMock):
        reader = PasswordReader(mock_user_manager)

        # Unit test of _decrypt_password()'s own wiring: mock decrypt (the
        # crypto-module boundary) rather than depending on real AEAD
        # decryption succeeding -- that's covered by test_crypto.py.
        with patch(
            "passlair.core.readers.password_reader.decrypt",
            return_value=password.encode("utf-8"),
        ) as mock_decrypt:
            test_data = reader._decrypt_password(entry, dek)

        mock_decrypt.assert_called_once_with(entry.password, entry.nonce, dek)
        assert test_data == {"login": data["login"], "password": password}

    def test_retrieve_password(self, mock_user_manager: MagicMock):
        reader = PasswordReader(mock_user_manager)
        with patch.object(PasswordReader, "_fetch_row", return_value=entry):
            test_data = reader._retrieve_password(data["service_name"])

        # TODO: maybe more asserts?
        assert isinstance(test_data, VaultEntry)

    def test_get_all_passwords(self, mock_user_manager: MagicMock):
        reader = PasswordReader(mock_user_manager)
        entries = [entry, VaultEntry(**data)]

        with patch("passlair.core.readers.password_reader.db") as mock_db:
            mock_session = MagicMock()
            mock_db.session.return_value.__enter__.return_value = mock_session
            mock_db.session.return_value.__exit__.return_value = False
            mock_session.query.return_value.filter_by.return_value.all.return_value = (
                entries
            )

            test_data = reader.get_all_passwords()

        assert test_data == entries
        mock_user_manager.get_session_key.assert_called_once()
        mock_session.query.assert_called_once_with(VaultEntry)
        mock_session.query.return_value.filter_by.assert_called_once_with(
            user_id=mock_user_manager.user_id
        )

    def test_get_all_passwords_empty_vault_returns_empty_list(
        self, mock_user_manager: MagicMock
    ):
        """An authenticated user with no saved passwords is a normal state,
        not a failure -- it must not raise."""
        reader = PasswordReader(mock_user_manager)

        with patch("passlair.core.readers.password_reader.db") as mock_db:
            mock_session = MagicMock()
            mock_db.session.return_value.__enter__.return_value = mock_session
            mock_db.session.return_value.__exit__.return_value = False
            mock_session.query.return_value.filter_by.return_value.all.return_value = (
                []
            )

            test_data = reader.get_all_passwords()

        assert test_data == []


class TestNegative:
    def test_invalid_init(self):
        """Ensure initialization raises a TypeError if user object doesn't meet requirements."""
        with pytest.raises(TypeError):
            _ = PasswordReader(None)

    def test_get_pass_for_when_service_does_not_exist(self, mock_user_manager: MagicMock):
        """Ensure get_pass_for raises an exception or handles a missing row gracefully."""
        reader = PasswordReader(mock_user_manager)
        with (
            patch.object(PasswordReader, "_retrieve_password", return_value=None),
            pytest.raises(KeyError),
        ):
            _ = reader.get_pass_for(data["service_name"])

    def test_retrieve_password_returns_none_if_row_missing(self, mock_user_manager: MagicMock):
        """Verify that _retrieve_password handles empty database results gracefully."""
        reader = PasswordReader(mock_user_manager)

        # Simulate database finding absolutely nothing
        with patch.object(PasswordReader, "_fetch_row", return_value=None):
            test_data = reader._retrieve_password("unknown_service")

            # If your architecture returns None instead of raising an error here
            assert test_data is None

    def test_get_all_passwords_without_active_session_raises_permission_error(
        self, mock_user_manager: MagicMock
    ):
        """No active session must be distinguishable from an empty vault --
        both would otherwise hit the DB with user_id=None and come back
        empty, so this has to be rejected before the query runs."""
        reader = PasswordReader(mock_user_manager)
        mock_user_manager.get_session_key.side_effect = PermissionError(
            "No active secure session. Please log in."
        )

        with patch("passlair.core.readers.password_reader.db") as mock_db:
            with pytest.raises(PermissionError):
                _ = reader.get_all_passwords()

            mock_db.session.assert_not_called()

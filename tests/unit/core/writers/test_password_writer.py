from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from passlair.core.crypto import encrypt
from passlair.core.models.vault_entry import VaultEntry
from passlair.core.writers.password_writer import PasswordWriter
from passlair.dataclasses.password_data import PasswordCreation

REAL_DEK = b"a_real_32_byte_session_key_here!"

password = "password321"
data = {
    "user_id": "string_id",
    "service_name": "service123",
    "login": "my_login",
    "password": password.encode("utf-8"),
    "nonce": b"11",
}
entry = VaultEntry(**data)
password_data = PasswordCreation(**data)


def make_import_entry(
    service: str, login: str, password: str
) -> dict[str, dict[str, str]]:
    return {service: {"login": login, "password": password}}


def patch_db_for_query(existing: list[VaultEntry]) -> tuple[MagicMock, MagicMock]:
    """Returns (db_patcher_target_value, mock_session) for save_passwords tests:
    a mock `db` whose `session()` context manager yields a session whose
    `query(...).filter_by(...).all()` returns `existing`."""
    mock_session = MagicMock()
    mock_session.query.return_value.filter_by.return_value.all.return_value = existing
    mock_db = MagicMock()
    mock_db.session.return_value.__enter__.return_value = mock_session
    mock_db.session.return_value.__exit__.return_value = False
    return mock_db, mock_session


class TestPositive:
    def test_init_assign_user_manager(self, mock_user_manager: MagicMock):
        writer = PasswordWriter(user=mock_user_manager)

        assert writer.user.user_id == "string_id"
        assert writer.user.get_session_key() == "session_key"

    def test_preparing_data(self, mock_user_manager: MagicMock):
        login, password, service = "login", "password", "service"
        return_values = ("password", b"12")
        writer = PasswordWriter(user=mock_user_manager)
        with patch.object(
            PasswordWriter,
            "_encrypt_password",
            return_value=return_values,
        ):
            test_data = writer._prepare_data(
                service=service, login=login, password=password
            )

        assert test_data.login == login
        assert test_data.password == b"password"
        assert test_data.service_name == service
        assert test_data.nonce == return_values[1]

    def test_save_password(
        self, mock_user_manager: MagicMock, mock_db_session: tuple[MagicMock, MagicMock]
    ):
        mock_session, _ = mock_db_session
        writer = PasswordWriter(user=mock_user_manager)
        with (
            patch.object(
                PasswordWriter,
                "_prepare_data",
                return_value=password_data,
            ) as mock_prepare,
            patch.object(
                PasswordWriter, "_add_or_update", return_value=password_data
            ) as mock_add,
            patch("passlair.core.writers.password_writer.db", mock_session),
        ):
            test_data = writer.save_password(
                service=password_data.service_name,
                login=password_data.login,
                password=password,
            )

        assert test_data

        mock_add.assert_called_once_with(password_data)
        mock_prepare.assert_called_once_with(
            password_data.service_name,
            password_data.login,
            password,
        )

    def test_add_or_update(self, mock_user_manager: MagicMock):
        writer = PasswordWriter(mock_user_manager)
        with (
            patch.object(PasswordWriter, "_fetch_row", return_value=True),
            patch.object(PasswordWriter, "_new_password", return_value=True),
            patch.object(PasswordWriter, "_update_password", return_value=True),
        ):
            test_data = writer._add_or_update(password_data)

        assert test_data

    def test_update_password(self, mock_user_manager: MagicMock):
        writer = PasswordWriter(mock_user_manager)
        test_data = writer._update_password(password_data, entry)

        assert test_data.login == data["login"]
        assert test_data.nonce == data["nonce"]
        assert test_data.password == data["password"]

    def test_new_password(self, mock_user_manager: MagicMock):
        writer = PasswordWriter(mock_user_manager)
        test_data = writer._new_password(password_data)

        assert test_data.login == data["login"]
        assert test_data.nonce == data["nonce"]
        assert test_data.password == data["password"]

    def test_encrypt_password(self, mock_user_manager: MagicMock):
        """Regression guard: passlair_crypto only accepts real bytes, not bytearray."""
        writer = PasswordWriter(mock_user_manager)
        dek = b"a_real_32_byte_session_key_here!"

        enc_pass, nonce = writer._encrypt_password(password, dek)

        assert isinstance(enc_pass, bytes)
        assert isinstance(nonce, bytes)
        assert len(nonce) == 12
        assert enc_pass != password.encode("utf-8")

    def test_save_passwords_inserts_all_when_none_exist(
        self, mock_user_manager: MagicMock
    ) -> None:
        mock_db, mock_session = patch_db_for_query(existing=[])
        writer = PasswordWriter(mock_user_manager)
        first = PasswordCreation(
            user_id="string_id",
            service_name="github.com",
            login="login_a",
            password=b"cipher_a",
            nonce=b"11",
        )
        second = PasswordCreation(
            user_id="string_id",
            service_name="gitlab.com",
            login="login_b",
            password=b"cipher_b",
            nonce=b"22",
        )

        with (
            patch.object(PasswordWriter, "_prepare_data", side_effect=[first, second]),
            patch("passlair.core.writers.password_writer.db", mock_db),
        ):
            writer.save_passwords(
                {
                    **make_import_entry("github.com", "login_a", "pw_a"),
                    **make_import_entry("gitlab.com", "login_b", "pw_b"),
                }
            )

        assert mock_session.add.call_count == 2
        added_services = {
            call.args[0].service_name for call in mock_session.add.call_args_list
        }
        assert added_services == {"github.com", "gitlab.com"}

    def test_save_passwords_skips_unchanged_entry_without_reencrypting(
        self, mock_user_manager: MagicMock
    ) -> None:
        """A re-imported service whose login/password decrypt to the exact
        values already stored should be left untouched -- and, since
        deciding that requires nothing but the existing ciphertext, it
        should never even reach _prepare_data (no pointless re-encryption)."""
        mock_user_manager.get_session_key.return_value = REAL_DEK
        ciphertext, nonce = encrypt(b"pw_a", REAL_DEK)
        existing_entry = VaultEntry(
            user_id="string_id",
            service_name="github.com",
            login="login_a",
            password=ciphertext,
            nonce=nonce,
        )
        mock_db, mock_session = patch_db_for_query(existing=[existing_entry])
        writer = PasswordWriter(mock_user_manager)

        with (
            patch.object(PasswordWriter, "_prepare_data") as mock_prepare,
            patch("passlair.core.writers.password_writer.db", mock_db),
        ):
            writer.save_passwords(make_import_entry("github.com", "login_a", "pw_a"))

        mock_prepare.assert_not_called()
        mock_session.add.assert_not_called()

    def test_save_passwords_updates_entry_when_password_changed(
        self, mock_user_manager: MagicMock
    ) -> None:
        """An existing service re-imported with a different plaintext
        password must be updated in place (not skipped, not added again)."""
        mock_user_manager.get_session_key.return_value = REAL_DEK
        old_ciphertext, old_nonce = encrypt(b"old_pw", REAL_DEK)
        existing_entry = VaultEntry(
            user_id="string_id",
            service_name="github.com",
            login="login_a",
            password=old_ciphertext,
            nonce=old_nonce,
        )
        mock_db, mock_session = patch_db_for_query(existing=[existing_entry])
        writer = PasswordWriter(mock_user_manager)

        with patch("passlair.core.writers.password_writer.db", mock_db):
            writer.save_passwords(make_import_entry("github.com", "login_a", "new_pw"))

        mock_session.add.assert_not_called()
        assert existing_entry.password != old_ciphertext
        assert existing_entry.nonce != old_nonce

    def test_save_passwords_updates_entry_when_login_changed(
        self, mock_user_manager: MagicMock
    ) -> None:
        """Same plaintext password, but a different login, must also count
        as changed -- login is part of what "unchanged" means."""
        mock_user_manager.get_session_key.return_value = REAL_DEK
        ciphertext, nonce = encrypt(b"pw_a", REAL_DEK)
        existing_entry = VaultEntry(
            user_id="string_id",
            service_name="github.com",
            login="old_login",
            password=ciphertext,
            nonce=nonce,
        )
        mock_db, mock_session = patch_db_for_query(existing=[existing_entry])
        writer = PasswordWriter(mock_user_manager)

        with patch("passlair.core.writers.password_writer.db", mock_db):
            writer.save_passwords(make_import_entry("github.com", "new_login", "pw_a"))

        mock_session.add.assert_not_called()
        assert existing_entry.login == "new_login"

    def test_is_unchanged_true_for_matching_login_and_password(
        self, mock_user_manager: MagicMock
    ) -> None:
        writer = PasswordWriter(mock_user_manager)
        ciphertext, nonce = encrypt(b"pw_a", REAL_DEK)
        existing_entry = VaultEntry(
            user_id="string_id",
            service_name="github.com",
            login="login_a",
            password=ciphertext,
            nonce=nonce,
        )

        assert writer._is_unchanged(existing_entry, "login_a", "pw_a", REAL_DEK) is True

    def test_is_unchanged_false_when_login_differs_without_decrypting(
        self, mock_user_manager: MagicMock
    ) -> None:
        """A login mismatch alone should be enough to report "changed" --
        no need to spend a decrypt call on it."""
        writer = PasswordWriter(mock_user_manager)
        existing_entry = VaultEntry(
            user_id="string_id",
            service_name="github.com",
            login="old_login",
            password=b"irrelevant-ciphertext",
            nonce=b"irrelevant12",
        )

        with patch(
            "passlair.core.writers.password_writer.decrypt"
        ) as mock_decrypt:
            result = writer._is_unchanged(
                existing_entry, "new_login", "pw_a", REAL_DEK
            )

        assert result is False
        mock_decrypt.assert_not_called()


class TestNegative:
    def test_init_fails_with_invalid_user_manager(self):
        """Ensure initialization raises a TypeError if user object doesn't meet requirements."""
        # Testing what happens if None or an invalid type is passed as the user session manager
        with pytest.raises(TypeError):
            _ = PasswordWriter(user=None)

    def test_preparing_data_with_empty_fields(self, mock_user_manager: MagicMock):
        """Ensure data preparation raises ValueErrors on bad or blank inputs."""
        writer = PasswordWriter(user=mock_user_manager)

        with pytest.raises(ValueError):
            _ = writer._prepare_data(service="", login="my_login", password="password")

    def test_encrypt_password_fails_if_session_key_invalid(
        self, mock_user_manager: MagicMock
    ):
        """Verify encryption mechanism crashes gracefully if session key is compromised/empty."""
        writer = PasswordWriter(user=mock_user_manager)

        # Override the session key to look like an expired or invalid state
        mock_user_manager.get_session_key.return_value = None

        with pytest.raises((ValueError, TypeError)):
            _ = writer._encrypt_password(password, mock_user_manager.get_session_key())

    def test_save_password_rolls_back_on_db_error(
        self, mock_user_manager: MagicMock, mock_db_session: tuple[MagicMock, MagicMock]
    ):
        """Ensure that if the DB breaks down, save_password passes the exception up."""
        mock_session, _ = mock_db_session
        writer = PasswordWriter(user=mock_user_manager)

        # Simulate a crash inside your _add_or_update phase (e.g., unique constraint failure)
        with (
            patch.object(PasswordWriter, "_prepare_data", return_value=password_data),
            patch.object(
                PasswordWriter,
                "_add_or_update",
                side_effect=SQLAlchemyError("DB Operational Error"),
            ),
            patch("passlair.core.writers.password_writer.db", mock_session),
        ):
            with pytest.raises(SQLAlchemyError, match="DB Operational Error"):
                _ = writer.save_password(
                    service=password_data.service_name,
                    login=password_data.login,
                    password=password,
                )

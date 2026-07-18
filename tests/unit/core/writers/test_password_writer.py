from unittest.mock import patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from passlair.core.models.vault_entry import VaultEntry
from passlair.core.writers.password_writer import PasswordWriter
from passlair.dataclasses.password_data import PasswordCreation

password = "password321"
data = {
    "user_id": "string_id",
    "service_name": "service123",
    "login": "my_login",
    "password": password,
    "nonce": "11",
}
entry = VaultEntry(**data)
password_data = PasswordCreation(**data)


class TestPositive:
    def test_init_assign_user_manager(self, mock_user_manager):
        writer = PasswordWriter(user=mock_user_manager)

        assert writer.user.user_id == "string_id"
        assert writer.user.get_session_key() == "session_key"

    def test_preparing_data(self, mock_user_manager):
        login, password, service = "login", "password", "service"
        return_values = ("password", "12")
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
        assert test_data.password == "password"
        assert test_data.service_name == service
        assert test_data.nonce == return_values[1]

    def test_save_password(self, mock_user_manager, mock_db_session):
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

    def test_add_or_update(self, mock_user_manager):
        writer = PasswordWriter(mock_user_manager)
        with (
            patch.object(PasswordWriter, "_fetch_row", return_value=True),
            patch.object(PasswordWriter, "_new_password", return_value=True),
            patch.object(PasswordWriter, "_update_password", return_value=True),
        ):
            test_data = writer._add_or_update(password_data)

        assert test_data

    def test_update_password(self, mock_user_manager):
        writer = PasswordWriter(mock_user_manager)
        test_data = writer._update_password(password_data, entry)

        assert test_data.login == data["login"]
        assert test_data.nonce == data["nonce"]
        assert test_data.password == data["password"]

    def test_new_password(self, mock_user_manager):
        writer = PasswordWriter(mock_user_manager)
        test_data = writer._new_password(password_data)

        assert test_data.login == data["login"]
        assert test_data.nonce == data["nonce"]
        assert test_data.password == data["password"]

    # FIXME: integration test
    # def test_encrypt_password(self, mock_user_manager):
    #     writer = PasswordWriter(mock_user_manager)
    #     enc_pass, nonce = writer._encrypt_password(
    #         password, mock_user_manager.get_session_key()
    #     )

    #     assert isinstance(password, str)  # uncomment after implementing encryption function
    #     assert isinstance(nonce, str)
    #     assert enc_pass != password


class TestNegative:
    def test_init_fails_with_invalid_user_manager(self):
        """Ensure initialization raises a TypeError if user object doesn't meet requirements."""
        # Testing what happens if None or an invalid type is passed as the user session manager
        with pytest.raises(TypeError):
            PasswordWriter(user=None)

    def test_preparing_data_with_empty_fields(self, mock_user_manager):
        """Ensure data preparation raises ValueErrors on bad or blank inputs."""
        writer = PasswordWriter(user=mock_user_manager)

        # Testing if your design rejects blank service names or empty passwords
        with pytest.raises(ValueError):
            writer._prepare_data(service="", login="my_login", password="password")

    def test_encrypt_password_fails_if_session_key_invalid(self, mock_user_manager):
        """Verify encryption mechanism crashes gracefully if session key is compromised/empty."""
        writer = PasswordWriter(user=mock_user_manager)

        # Override the session key to look like an expired or invalid state
        mock_user_manager.get_session_key.return_value = None

        with pytest.raises((ValueError, TypeError)):
            writer._encrypt_password(password, mock_user_manager.get_session_key())

    def test_save_password_rolls_back_on_db_error(
        self, mock_user_manager, mock_db_session
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
                writer.save_password(
                    service=password_data.service_name,
                    login=password_data.login,
                    password=password,
                )

    def test_add_or_update_routing_failure(self, mock_user_manager):
        """Verify system response if internal generation steps return incomplete/None objects."""
        writer = PasswordWriter(mock_user_manager)

        # Simulate a scenario where _new_password fails to build an entry and returns None
        with (
            patch.object(
                PasswordWriter, "_fetch_row", return_value=False
            ),  # Simulates entry not found
            patch.object(PasswordWriter, "_new_password", return_value=None),
        ):
            # If your code expects a valid object, this should fail a check or throw an error
            with pytest.raises((ValueError, AttributeError)):
                writer._add_or_update(password_data)

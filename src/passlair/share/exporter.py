from typing import override
import json
import logging
import pyperclip

from passlair_crypto.package import decrypt_password

from ..core.auth.user_manager import UserManager
from ..core.readers.password_reader import PasswordReader
from ..base.abstract.base_exporter import BaseExporter

logger = logging.getLogger(__name__)


class Exporter(BaseExporter):
    def __init__(self, manager: UserManager) -> None:
        self.__manager = manager

    def _retrieve_passwords(self) -> dict[str, dict[str, str]]:
        """Returns {service: {"login": ..., "password": ...}} for every vault
        entry belonging to the logged-in user."""
        vault_entries = PasswordReader(self.__manager).get_all_passwords()
        result: dict[str, dict[str, str]] = {}
        for entry in vault_entries:
            password = decrypt_password(
                entry.password, entry.nonce, self.__manager.get_session_key()
            ).decode("utf-8")

            result[entry.service_name] = {"login": entry.login, "password": password}

        logger.debug(
            "_retrieve_passwords: decrypted %d entries for export", len(result)
        )
        return result

    def export_to_txt(self, path: str) -> None:
        with open(path, "w") as file:
            _ = file.write(self._export_txt())

    def export_to_csv(self, path: str) -> None:
        with open(path, "w") as file:
            if not (passwords := self._retrieve_passwords()):
                logger.info("export_to_csv: vault empty, wrote placeholder to %r", path)
                _ = file.write(",,")
                return
            result = "service,login,password\n"
            for service, credentials in passwords.items():
                result += (
                    f"{service},{credentials['login']},{credentials['password']}\n"
                )

            _ = file.write(result)

    def export_to_json(self, path: str) -> None:
        with open(path, "w") as file:
            if not (passwords := self._retrieve_passwords()):
                logger.info(
                    "export_to_json: vault empty, wrote empty object to %r", path
                )
                _ = file.write("{}")
                return

            json.dump(passwords, file)
            logger.info("export_to_json: wrote %d entries to %r", len(passwords), path)

    @override
    def export_to_file(self, path: str, fmt: str) -> None:
        """Dispatches to export_to_txt/csv/json based on fmt ('txt'|'csv'|'json').

        Raises ValueError for an unrecognized fmt.
        """
        logger.info("export_to_file: exporting to %r as %s", path, fmt)
        match fmt:
            case "json":
                self.export_to_json(path)
            case "csv":
                self.export_to_csv(path)
            case "txt":
                self.export_to_txt(path)
            case _:
                logger.warning("export_to_file: unrecognized format %r", fmt)
                raise ValueError("Unrecognized format. Choose txt/json/csv.")

    def get_clipboard_json(self) -> None:
        string = json.dumps(self._retrieve_passwords())
        pyperclip.copy(string)

    def get_clipboard_txt(self) -> None:
        result = self._export_txt()
        pyperclip.copy(result)

    def _export_txt(self) -> str:
        if not (passwords := self._retrieve_passwords()):
            logger.info("_export_txt: vault is empty")
        result = ""
        for service, credentials in passwords.items():
            result += f"service={service} / login={credentials['login']} / password={credentials['password']}\n"

        return result

    @override
    def export_to_clipboard(self, fmt: str = "txt") -> None:
        """Copies the export to the clipboard (via pyperclip) formatted as
        'txt' or 'json'."""
        match fmt:
            case "json":
                logger.info("export_to_clipboard: copying json to clipboard")
                self.get_clipboard_json()
            case "txt":
                logger.info("export_to_clipboard: copying txt to clipboard")
                self.get_clipboard_txt()
            case _:
                logger.error("export_to_clipboard: unrecognized format %r", fmt)
                raise ValueError("Unrecognized format. Choose txt/json")

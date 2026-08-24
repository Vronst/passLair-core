from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from passlair.core.auth.user_manager import UserManager
from passlair.core.readers.password_reader import PasswordReader
from passlair.share.exporter import Exporter
from passlair.share.importer import Importer

FORMATS = [("json", ".json"), ("csv", ".csv"), ("txt", ".txt")]


class TestPositive:
    def compare_vault(
        self, manager: UserManager, passwords: list[dict[str, str]]
    ) -> None:
        output = Exporter(manager)._retrieve_passwords()
        for credentials in passwords:
            service = credentials["service"]
            assert service in output
            assert output[service]["login"] == credentials["login"]
            assert output[service]["password"] == credentials["password"]

    @pytest.mark.parametrize("fmt, suffix", FORMATS)
    def test_round_trip_export_then_import_into_new_user(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        register_user2: dict[str, str],
        tmp_path: Path,
        fmt: str,
        suffix: str,
    ) -> None:
        """What Exporter writes, Importer must be able to read back --
        across a different user's vault, so this also proves the file
        carries the data rather than relying on anything session-local."""
        source_manager, passwords = user_manager_with_passwords
        out_file = tmp_path / f"export{suffix}"
        Exporter(source_manager).export_to_file(str(out_file), fmt)

        target_manager = UserManager()
        assert target_manager.login(
            register_user2["username"], register_user2["password"]
        )
        Importer(target_manager).import_from_file(str(out_file), fmt)

        self.compare_vault(target_manager, passwords)
        assert len(PasswordReader(target_manager).get_all_passwords()) == len(passwords)

    @pytest.mark.parametrize("fmt, suffix", FORMATS)
    def test_reimporting_own_export_does_not_duplicate(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
        fmt: str,
        suffix: str,
    ) -> None:
        """Re-importing a user's own unchanged export back into the same
        vault must be a no-op (save_passwords' unchanged-skip path), not
        create duplicate rows."""
        manager, passwords = user_manager_with_passwords
        out_file = tmp_path / f"export{suffix}"
        Exporter(manager).export_to_file(str(out_file), fmt)

        Importer(manager).import_from_file(str(out_file), fmt)

        entries = PasswordReader(manager).get_all_passwords()
        assert len(entries) == len(passwords)
        self.compare_vault(manager, passwords)

    def test_round_trip_json_clipboard(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        register_user2: dict[str, str],
        mocker: MockerFixture,
    ) -> None:
        source_manager, passwords = user_manager_with_passwords
        clipboard: dict[str, str] = {}
        _ = mocker.patch(
            "passlair.share.exporter.pyperclip.copy",
            side_effect=lambda text: clipboard.__setitem__("value", text),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste",
            side_effect=lambda: clipboard["value"],
        )

        Exporter(source_manager).export_to_clipboard(fmt="json")

        target_manager = UserManager()
        assert target_manager.login(
            register_user2["username"], register_user2["password"]
        )
        Importer(target_manager).import_from_clipboard("json")

        self.compare_vault(target_manager, passwords)

    def test_round_trip_txt_clipboard(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        register_user2: dict[str, str],
        mocker: MockerFixture,
    ) -> None:
        source_manager, passwords = user_manager_with_passwords
        clipboard: dict[str, str] = {}
        _ = mocker.patch(
            "passlair.share.exporter.pyperclip.copy",
            side_effect=lambda text: clipboard.__setitem__("value", text),  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
        )
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste",
            side_effect=lambda: clipboard["value"],
        )

        Exporter(source_manager).export_to_clipboard(fmt="txt")

        target_manager = UserManager()
        assert target_manager.login(
            register_user2["username"], register_user2["password"]
        )
        Importer(target_manager).import_from_clipboard("txt")

        self.compare_vault(target_manager, passwords)


class TestNegative:
    @pytest.mark.parametrize("fmt, suffix", FORMATS)
    def test_round_trip_empty_vault_imports_nothing(
        self,
        register_user2: dict[str, str],
        tmp_path: Path,
        fmt: str,
        suffix: str,
    ) -> None:
        """Exporting and re-importing an empty vault must not error and
        must not create any entries."""
        manager = UserManager()
        assert manager.login(register_user2["username"], register_user2["password"])
        out_file = tmp_path / f"export{suffix}"
        Exporter(manager).export_to_file(str(out_file), fmt)

        Importer(manager).import_from_file(str(out_file), fmt)

        assert PasswordReader(manager).get_all_passwords() == []

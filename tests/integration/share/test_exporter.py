import csv
import json
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from passlair.share.exporter import Exporter
from passlair.core.auth.user_manager import UserManager


class TestPositive:
    def compare_output(
        self, output: dict[str, dict[str, str]], passwords: list[dict[str, str]]
    ) -> None:
        for credentials in passwords:
            service = credentials["service"]
            expected_login = credentials["login"]
            expected_password = credentials["password"]

            assert service in output
            assert isinstance(output[service], dict)
            assert output[service]["login"] == expected_login
            assert output[service]["password"] == expected_password

    def test_exporter_retrieve_passwords(
        self, user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]]
    ) -> None:
        user_manager, passwords = user_manager_with_passwords
        exporter = Exporter(user_manager)
        output = exporter._retrieve_passwords()
        assert output is not None
        assert isinstance(output, dict)

        self.compare_output(output, passwords)

    def test_exporter_export_to_txt(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
    ) -> None:
        user_manager, passwords = user_manager_with_passwords
        exporter = Exporter(user_manager)
        out_file = tmp_path / "export.txt"

        exporter.export_to_txt(str(out_file))

        content = out_file.read_text()
        for credentials in passwords:
            assert credentials["service"] in content
            assert credentials["login"] in content
            assert credentials["password"] in content

    def test_exporter_export_to_csv(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
    ) -> None:
        user_manager, passwords = user_manager_with_passwords
        exporter = Exporter(user_manager)
        out_file = tmp_path / "export.csv"

        exporter.export_to_csv(str(out_file))

        with out_file.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
        output = {
            row["service"]: {"login": row["login"], "password": row["password"]}
            for row in rows
        }
        self.compare_output(output, passwords)

    def test_exporter_export_to_json(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
    ) -> None:
        user_manager, passwords = user_manager_with_passwords
        exporter = Exporter(user_manager)
        out_file = tmp_path / "export.json"

        exporter.export_to_json(str(out_file))

        output = json.loads(out_file.read_text())
        self.compare_output(output, passwords)

    @pytest.mark.parametrize(
        "fmt, suffix",
        [("txt", ".txt"), ("csv", ".csv"), ("json", ".json")],
    )
    def test_exporter_export_to_file_dispatches_by_format(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
        fmt: str,
        suffix: str,
    ) -> None:
        user_manager, _ = user_manager_with_passwords
        exporter = Exporter(user_manager)
        direct_file = tmp_path / f"direct{suffix}"
        dispatched_file = tmp_path / f"dispatched{suffix}"

        getattr(exporter, f"export_to_{fmt}")(str(direct_file))
        exporter.export_to_file(str(dispatched_file), fmt)

        assert dispatched_file.read_text() == direct_file.read_text()

    def export_to_clipboard(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        mocker: MockerFixture,
        fmt: str,
    ) -> tuple[list[dict[str, str]], str]:
        user_manager, passwords = user_manager_with_passwords
        copy = mocker.patch("passlair.share.exporter.pyperclip.copy")
        exporter = Exporter(user_manager)

        exporter.export_to_clipboard(fmt=fmt)

        copy.assert_called_once()
        return passwords, copy.call_args.args[0]

    def test_exporter_export_to_clipboard_txt(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        mocker: MockerFixture,
    ) -> None:
        passwords, copied = self.export_to_clipboard(
            user_manager_with_passwords, mocker, "txt"
        )
        for credentials in passwords:
            assert credentials["service"] in copied
            assert credentials["login"] in copied
            assert credentials["password"] in copied

    def test_exporter_export_to_clipboard_json(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        mocker: MockerFixture,
    ) -> None:
        passwords, copied = self.export_to_clipboard(
            user_manager_with_passwords, mocker, "json"
        )
        output = json.loads(copied)
        self.compare_output(output, passwords)


class TestNegative:
    def make_exporter_for_empty_vault(self, register_user2: dict[str, str]) -> Exporter:
        user_manager = UserManager()
        assert user_manager.login(
            register_user2["username"], register_user2["password"]
        )
        return Exporter(user_manager)

    def test_exporter_retrieve_passwords(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        register_user2: dict[str, str],
    ) -> None:
        exporter = self.make_exporter_for_empty_vault(register_user2)

        output = exporter._retrieve_passwords()
        assert output is not None
        assert isinstance(output, dict)
        assert not output

    @pytest.mark.parametrize("fmt, suffix", [("txt", ".txt"), ("json", ".json")])
    def test_exporter_export_empty_vault(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        register_user2: dict[str, str],
        tmp_path: Path,
        fmt: str,
        suffix: str,
    ) -> None:
        exporter = self.make_exporter_for_empty_vault(register_user2)
        out_file = tmp_path / f"export{suffix}"

        getattr(exporter, f"export_to_{fmt}")(str(out_file))

        content = out_file.read_text()
        if fmt == "json":
            assert json.loads(content) == {}
        else:
            assert content.strip() == ""

    def test_exporter_export_to_file_rejects_unknown_format(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
        tmp_path: Path,
    ) -> None:
        user_manager, _ = user_manager_with_passwords
        exporter = Exporter(user_manager)

        with pytest.raises(ValueError):
            exporter.export_to_file(str(tmp_path / "export.xml"), "xml")

    def test_exporter_retrieve_passwords_without_active_session(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
    ) -> None:
        user_manager, _ = user_manager_with_passwords
        user_manager.logout()
        exporter = Exporter(user_manager)

        with pytest.raises(PermissionError):
            _ = exporter._retrieve_passwords()

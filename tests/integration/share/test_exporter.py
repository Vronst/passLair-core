import csv
import io
import json
import stat
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from passlair.core.auth.user_manager import UserManager
from passlair.core.writers.password_writer import PasswordWriter
from passlair.share.exporter import Exporter

type Vault = dict[str, dict[str, str]]


def as_vault(passwords: list[dict[str, str]]) -> Vault:
    return {
        p["service"]: {"login": p["login"], "password": p["password"]}
        for p in passwords
    }


def parse_csv(text: str) -> Vault:
    rows = csv.DictReader(io.StringIO(text, newline=""))
    return as_vault(list(rows))


def parse_txt(text: str) -> list[str]:
    return text.splitlines()


@pytest.fixture
def exporter(
    user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
) -> Exporter:
    return Exporter(user_manager_with_passwords[0])


@pytest.fixture
def expected(
    user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
) -> Vault:
    return as_vault(user_manager_with_passwords[1])


@pytest.fixture
def empty_exporter(register_user2: dict[str, str]) -> Exporter:
    user_manager = UserManager()
    assert user_manager.login(register_user2["username"], register_user2["password"])
    return Exporter(user_manager)


class TestPositive:
    def test_retrieve_passwords_decrypts_every_entry(
        self, exporter: Exporter, expected: Vault
    ) -> None:
        assert exporter._retrieve_passwords() == expected

    def test_serialize_json(self, exporter: Exporter, expected: Vault) -> None:
        assert json.loads(exporter.serialize("json")) == expected

    def test_serialize_csv(self, exporter: Exporter, expected: Vault) -> None:
        text = exporter.serialize("csv")

        assert text.startswith("service,login,password\r\n")
        assert parse_csv(text) == expected

    def test_serialize_txt_writes_one_line_per_entry(
        self, exporter: Exporter, expected: Vault
    ) -> None:
        lines = parse_txt(exporter.serialize("txt"))

        assert sorted(lines) == sorted(
            f"service={s} / login={c['login']} / password={c['password']}"
            for s, c in expected.items()
        )

    def test_serialize_csv_quotes_newline_comma_and_quote(
        self, register_user: dict[str, str]
    ) -> None:
        manager = UserManager()
        assert manager.login(register_user["username"], register_user["password"])
        password = 'multi\nline, "quoted"'
        PasswordWriter(manager).save_password("svc", "me", password)

        text = Exporter(manager).serialize("csv")

        assert parse_csv(text) == {"svc": {"login": "me", "password": password}}

    @pytest.mark.parametrize("suffix", [".txt", ".json", ".csv", ".CSV"])
    def test_export_to_file_infers_format_from_suffix(
        self, exporter: Exporter, tmp_path: Path, suffix: str
    ) -> None:
        out_file = tmp_path / f"export{suffix}"

        exporter.export_to_file(str(out_file))

        fmt = suffix.lower().removeprefix(".")
        # read_bytes, not read_text: CSV's \r\n must reach disk untranslated.
        assert out_file.read_bytes() == exporter.serialize(fmt).encode()

    def test_export_to_file_explicit_format_overrides_suffix(
        self, exporter: Exporter, expected: Vault, tmp_path: Path
    ) -> None:
        out_file = tmp_path / "export.txt"

        exporter.export_to_file(str(out_file), "json")

        assert json.loads(out_file.read_text()) == expected

    def test_export_to_file_is_readable_by_owner_only(
        self, exporter: Exporter, tmp_path: Path
    ) -> None:
        out_file = tmp_path / "export.json"

        exporter.export_to_file(str(out_file))

        assert stat.S_IMODE(out_file.stat().st_mode) == 0o600

    @pytest.mark.parametrize("fmt", ["txt", "json", "csv"])
    def test_export_to_clipboard_copies_serialized_text(
        self, exporter: Exporter, mocker: MockerFixture, fmt: str
    ) -> None:
        copy = mocker.patch("passlair.share.exporter.pyperclip.copy")

        exporter.export_to_clipboard(fmt)

        copy.assert_called_once_with(exporter.serialize(fmt))

    @pytest.mark.parametrize(
        "fmt, text",
        [("json", "{}"), ("csv", "service,login,password\r\n"), ("txt", "")],
    )
    def test_serialize_empty_vault(
        self, empty_exporter: Exporter, fmt: str, text: str
    ) -> None:
        assert empty_exporter.serialize(fmt) == text


class TestNegative:
    def test_serialize_rejects_unknown_format_before_decrypting(
        self, exporter: Exporter, mocker: MockerFixture
    ) -> None:
        retrieve = mocker.patch.object(Exporter, "_retrieve_passwords")

        with pytest.raises(ValueError, match="Unrecognized format 'xml'"):
            _ = exporter.serialize("xml")

        retrieve.assert_not_called()

    @pytest.mark.parametrize("name", ["export.xml", "export", "export.json.bak"])
    def test_export_to_file_rejects_unknown_suffix_without_creating_file(
        self, exporter: Exporter, tmp_path: Path, name: str
    ) -> None:
        out_file = tmp_path / name

        with pytest.raises(ValueError, match="Unrecognized format"):
            exporter.export_to_file(str(out_file))

        assert not out_file.exists()

    @pytest.mark.parametrize("value", ["a\nb", "a\r", "a b", "a\x0c"])
    def test_serialize_txt_refuses_values_with_line_breaks(
        self, register_user: dict[str, str], value: str
    ) -> None:
        """txt is one entry per line; a line break would split the entry and
        the importer would skip both halves."""
        manager = UserManager()
        assert manager.login(register_user["username"], register_user["password"])
        PasswordWriter(manager).save_password("svc", "me", value)

        with pytest.raises(ValueError, match="line break"):
            _ = Exporter(manager).serialize("txt")

    def test_retrieve_passwords_without_active_session(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
    ) -> None:
        user_manager, _ = user_manager_with_passwords
        user_manager.logout()

        with pytest.raises(PermissionError):
            _ = Exporter(user_manager)._retrieve_passwords()

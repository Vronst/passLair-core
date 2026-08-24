import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from passlair.core.auth.user_manager import UserManager
from passlair.share.importer import Importer


@pytest.fixture
def mock_manager() -> MagicMock:
    return MagicMock(spec=UserManager)


class TestPositive:
    @pytest.mark.parametrize(
        "fmt, target",
        [
            ("txt", "import_from_txt"),
            ("json", "import_from_json"),
            ("csv", "import_from_csv"),
        ],
    )
    def test_import_from_file_dispatches_by_format(
        self, mocker: MockerFixture, mock_manager: MagicMock, fmt: str, target: str
    ) -> None:
        importer = Importer(mock_manager)
        mocked = mocker.patch.object(importer, target)

        importer.import_from_file("some/path", fmt)

        mocked.assert_called_once_with("some/path")

    @pytest.mark.parametrize(
        "fmt, target",
        [
            ("txt", "import_txt_from_clipboard"),
            ("json", "import_json_from_clipboard"),
        ],
    )
    def test_import_from_clipboard_dispatches_by_format(
        self, mocker: MockerFixture, mock_manager: MagicMock, fmt: str, target: str
    ) -> None:
        importer = Importer(mock_manager)
        mocked = mocker.patch.object(importer, target)

        importer.import_from_clipboard(fmt)

        mocked.assert_called_once_with()

    def test_import_from_file_dispatches_only_to_matching_format(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        txt = mocker.patch.object(importer, "import_from_txt")
        json_ = mocker.patch.object(importer, "import_from_json")
        csv_ = mocker.patch.object(importer, "import_from_csv")

        importer.import_from_file("some/path", "json")

        json_.assert_called_once_with("some/path")
        txt.assert_not_called()
        csv_.assert_not_called()

    def test_parse_txt_single_entry(self, mock_manager: MagicMock) -> None:
        importer = Importer(mock_manager)
        content = "service=github.com / login=me / password=p@ss!23\n"

        result = importer._parse_txt(content)

        assert result == {"github.com": {"login": "me", "password": "p@ss!23"}}

    def test_parse_txt_multiple_entries(self, mock_manager: MagicMock) -> None:
        importer = Importer(mock_manager)
        content = (
            "service=github.com / login=me / password=pw_a\n"
            "service=gitlab.com / login=me2 / password=pw_b\n"
        )

        result = importer._parse_txt(content)

        assert result == {
            "github.com": {"login": "me", "password": "pw_a"},
            "gitlab.com": {"login": "me2", "password": "pw_b"},
        }

    def test_parse_txt_value_with_slash_not_mistaken_for_delimiter(
        self, mock_manager: MagicMock
    ) -> None:
        """A bare "/" inside a value (not surrounded by spaces) must not be
        confused with the " / " field delimiter."""
        importer = Importer(mock_manager)
        content = "service=my/service / login=user/name / password=p/w\n"

        result = importer._parse_txt(content)

        assert result == {"my/service": {"login": "user/name", "password": "p/w"}}

    def test_parse_txt_skips_unparsable_lines_and_warns(
        self,
        mock_manager: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        importer = Importer(mock_manager)
        content = (
            "service=github.com / login=me / password=pw_a\n"
            "this line is garbage, not an entry\n"
            "\n"
            "service=gitlab.com / login=me2 / password=pw_b\n"
        )

        with caplog.at_level(logging.WARNING, logger="passlair.share.importer"):
            result = importer._parse_txt(content)

        assert result == {
            "github.com": {"login": "me", "password": "pw_a"},
            "gitlab.com": {"login": "me2", "password": "pw_b"},
        }
        assert "unparsable" in caplog.text.lower()
        # the blank line must not itself be reported as a skipped/malformed
        # entry -- only the one genuinely garbage line counts.
        assert "Skipped 1 unparsable" in caplog.text

    def test_import_from_csv_skips_malformed_rows_and_warns(
        self,
        mocker: MockerFixture,
        mock_manager: MagicMock,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        importer = Importer(mock_manager)
        csv_file = tmp_path / "export.csv"
        content = (
            "service,login,password\n"
            "github.com,me,pw_a\n"
            "incomplete.com,only_login\n"
            "gitlab.com,me2,pw_b\n"
        )
        _ = csv_file.write_text(content)
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        with caplog.at_level(logging.WARNING, logger="passlair.share.importer"):
            importer.import_from_csv(str(csv_file))

        mock_save.assert_called_once_with(
            {
                "github.com": {"login": "me", "password": "pw_a"},
                "gitlab.com": {"login": "me2", "password": "pw_b"},
            }
        )
        assert "malformed" in caplog.text.lower()
        assert "Skipped 1 malformed" in caplog.text

    def test_import_from_csv_skips_header_row(
        self, mocker: MockerFixture, mock_manager: MagicMock, tmp_path: Path
    ) -> None:
        """Regression guard: csv.reader without a header skip previously
        imported the header row itself as a bogus entry."""
        importer = Importer(mock_manager)
        csv_file = tmp_path / "export.csv"
        _ = csv_file.write_text("service,login,password\ngithub.com,me,pw_a\n")
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        importer.import_from_csv(str(csv_file))

        mock_save.assert_called_once_with(
            {"github.com": {"login": "me", "password": "pw_a"}}
        )

    def test_import_from_txt_parses_file_and_saves(
        self, mocker: MockerFixture, mock_manager: MagicMock, tmp_path: Path
    ) -> None:
        importer = Importer(mock_manager)
        txt_file = tmp_path / "export.txt"
        _ = txt_file.write_text("service=github.com / login=me / password=pw_a\n")
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        importer.import_from_txt(str(txt_file))

        mock_save.assert_called_once_with(
            {"github.com": {"login": "me", "password": "pw_a"}}
        )

    def test_import_from_json_parses_file_and_saves(
        self, mocker: MockerFixture, mock_manager: MagicMock, tmp_path: Path
    ) -> None:
        importer = Importer(mock_manager)
        json_file = tmp_path / "export.json"
        data = {"github.com": {"login": "me", "password": "pw_a"}}
        _ = json_file.write_text(json.dumps(data))
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        importer.import_from_json(str(json_file))

        mock_save.assert_called_once_with(data)

    def test_import_txt_from_clipboard_parses_and_saves(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste",
            return_value="service=github.com / login=me / password=pw_a\n",
        )
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        importer.import_txt_from_clipboard()

        mock_save.assert_called_once_with(
            {"github.com": {"login": "me", "password": "pw_a"}}
        )

    def test_import_json_from_clipboard_parses_and_saves(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        data = {"github.com": {"login": "me", "password": "pw_a"}}
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste", return_value=json.dumps(data)
        )
        mock_save = mocker.patch.object(Importer, "_save_passwords")

        importer.import_json_from_clipboard()

        mock_save.assert_called_once_with(data)

    def test_save_passwords_calls_writer_when_data_present(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        mock_writer_cls = mocker.patch("passlair.share.importer.PasswordWriter")
        mock_writer = mock_writer_cls.return_value
        data = {"github.com": {"login": "me", "password": "pw_a"}}

        importer._save_passwords(data)

        mock_writer_cls.assert_called_once_with(mock_manager)
        mock_writer.save_passwords.assert_called_once_with(data)


class TestNegative:
    def test_import_from_file_rejects_unknown_format(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        txt = mocker.patch.object(importer, "import_from_txt")
        json_ = mocker.patch.object(importer, "import_from_json")
        csv_ = mocker.patch.object(importer, "import_from_csv")

        with pytest.raises(ValueError):
            importer.import_from_file("some/path", "xml")

        txt.assert_not_called()
        json_.assert_not_called()
        csv_.assert_not_called()

    def test_import_from_clipboard_rejects_unknown_format(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        txt = mocker.patch.object(importer, "import_txt_from_clipboard")
        json_ = mocker.patch.object(importer, "import_json_from_clipboard")

        with pytest.raises(ValueError):
            importer.import_from_clipboard("csv")

        txt.assert_not_called()
        json_.assert_not_called()

    def test_import_from_json_rejects_malformed_shape(
        self, mock_manager: MagicMock, tmp_path: Path
    ) -> None:
        importer = Importer(mock_manager)
        json_file = tmp_path / "export.json"
        _ = json_file.write_text(json.dumps(["not", "a", "dict"]))

        with pytest.raises(ValidationError):
            importer.import_from_json(str(json_file))

    def test_import_json_from_clipboard_rejects_malformed_shape(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste",
            return_value=json.dumps({"github.com": "not-a-dict"}),
        )

        with pytest.raises(ValidationError):
            importer.import_json_from_clipboard()

    def test_save_passwords_skips_writer_when_no_data(
        self, mocker: MockerFixture, mock_manager: MagicMock
    ) -> None:
        importer = Importer(mock_manager)
        mock_writer_cls = mocker.patch("passlair.share.importer.PasswordWriter")

        importer._save_passwords({})

        mock_writer_cls.assert_not_called()

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from passlair.core.auth.user_manager import UserManager
from passlair.dataclasses.import_result import ImportResult
from passlair.share.importer import Importer, ImportFormatError

GITHUB = {"github.com": {"login": "me", "password": "pw_a"}}

# The same single GitHub entry, written in each supported format.
CONTENT_BY_FORMAT = {
    "txt": "service=github.com / login=me / password=pw_a\n",
    "json": json.dumps(GITHUB),
    "csv": "service,login,password\r\ngithub.com,me,pw_a\r\n",
}


@pytest.fixture
def mock_manager() -> MagicMock:
    return MagicMock(spec=UserManager)


@pytest.fixture
def importer(mock_manager: MagicMock) -> Importer:
    return Importer(mock_manager)


@pytest.fixture
def mock_save(mocker: MockerFixture) -> MagicMock:
    return mocker.patch.object(Importer, "_save_passwords")


class TestPositive:
    @pytest.mark.parametrize("fmt", CONTENT_BY_FORMAT)
    def test_import_text_saves_parsed_entries_and_reports_counts(
        self, importer: Importer, mock_save: MagicMock, fmt: str
    ) -> None:
        result = importer.import_text(CONTENT_BY_FORMAT[fmt], fmt)

        mock_save.assert_called_once_with(GITHUB)
        assert result == ImportResult(imported=1, skipped=0)

    def test_import_text_empty_content_imports_nothing(
        self, importer: Importer, mocker: MockerFixture
    ) -> None:
        mock_writer_cls = mocker.patch("passlair.share.importer.PasswordWriter")

        result = importer.import_text("", "txt")

        assert result == ImportResult(imported=0, skipped=0)
        mock_writer_cls.assert_not_called()

    @pytest.mark.parametrize("suffix", [".txt", ".json", ".csv", ".JSON"])
    def test_import_from_file_infers_format_from_suffix(
        self, importer: Importer, mock_save: MagicMock, tmp_path: Path, suffix: str
    ) -> None:
        path = tmp_path / f"export{suffix}"
        _ = path.write_text(CONTENT_BY_FORMAT[suffix.lower().removeprefix(".")])

        result = importer.import_from_file(str(path))

        mock_save.assert_called_once_with(GITHUB)
        assert result == ImportResult(imported=1, skipped=0)

    def test_import_from_file_explicit_format_overrides_suffix(
        self, importer: Importer, mock_save: MagicMock, tmp_path: Path
    ) -> None:
        path = tmp_path / "export.txt"
        _ = path.write_text(CONTENT_BY_FORMAT["json"])

        _ = importer.import_from_file(str(path), "json")

        mock_save.assert_called_once_with(GITHUB)

    def test_import_from_clipboard_imports_pasted_text(
        self, importer: Importer, mock_save: MagicMock, mocker: MockerFixture
    ) -> None:
        _ = mocker.patch(
            "passlair.share.importer.pyperclip.paste",
            return_value=CONTENT_BY_FORMAT["txt"],
        )

        result = importer.import_from_clipboard("txt")

        mock_save.assert_called_once_with(GITHUB)
        assert result == ImportResult(imported=1, skipped=0)

    def test_parse_txt_multiple_entries(self, importer: Importer) -> None:
        content = (
            "service=github.com / login=me / password=pw_a\n"
            "service=gitlab.com / login=me2 / password=pw_b\n"
        )

        data, skipped = importer._parse_txt(content)

        assert data == {
            "github.com": {"login": "me", "password": "pw_a"},
            "gitlab.com": {"login": "me2", "password": "pw_b"},
        }
        assert skipped == 0

    def test_parse_txt_value_with_slash_not_mistaken_for_delimiter(
        self, importer: Importer
    ) -> None:
        """A bare "/" inside a value (not surrounded by spaces) must not be
        confused with the " / " field delimiter."""
        content = "service=my/service / login=user/name / password=p/w\n"

        data, _ = importer._parse_txt(content)

        assert data == {"my/service": {"login": "user/name", "password": "p/w"}}

    def test_parse_txt_skips_unparsable_lines_and_warns(
        self, importer: Importer, caplog: pytest.LogCaptureFixture
    ) -> None:
        content = (
            "service=github.com / login=me / password=pw_a\n"
            "this line is garbage, not an entry\n"
            "\n"
            "service=gitlab.com / login=me2 / password=pw_b\n"
        )

        with caplog.at_level(logging.WARNING, logger="passlair.share.importer"):
            data, skipped = importer._parse_txt(content)

        assert set(data) == {"github.com", "gitlab.com"}
        # the blank line must not count -- only the one garbage line does.
        assert skipped == 1
        assert "skipping unparsable line 2" in caplog.text

    def test_parse_csv_skips_header_and_malformed_rows(
        self, importer: Importer, caplog: pytest.LogCaptureFixture
    ) -> None:
        content = (
            "service,login,password\n"
            "github.com,me,pw_a\n"
            "incomplete.com,only_login\n"
            "gitlab.com,me2,pw_b\n"
        )

        with caplog.at_level(logging.WARNING, logger="passlair.share.importer"):
            data, skipped = importer._parse_csv(content)

        assert data == {
            "github.com": {"login": "me", "password": "pw_a"},
            "gitlab.com": {"login": "me2", "password": "pw_b"},
        }
        assert skipped == 1
        assert "skipping malformed row 3, missing ['password']" in caplog.text

    def test_parse_csv_keeps_newline_comma_and_quote_inside_quoted_field(
        self, importer: Importer
    ) -> None:
        """Regression guard: splitting on "\\n" before csv parsing turned
        the password 'p1\\nline2' into 'p1line2' without any error."""
        content = 'service,login,password\r\nsvc,me,"p1\nline2, ""q"""\r\n'

        data, skipped = importer._parse_csv(content)

        assert data == {"svc": {"login": "me", "password": 'p1\nline2, "q"'}}
        assert skipped == 0

    def test_save_passwords_calls_writer_when_data_present(
        self, importer: Importer, mock_manager: MagicMock, mocker: MockerFixture
    ) -> None:
        mock_writer_cls = mocker.patch("passlair.share.importer.PasswordWriter")

        importer._save_passwords(GITHUB)

        mock_writer_cls.assert_called_once_with(mock_manager)
        mock_writer_cls.return_value.save_passwords.assert_called_once_with(GITHUB)


class TestNegative:
    def test_import_text_rejects_unknown_format(
        self, importer: Importer, mock_save: MagicMock
    ) -> None:
        with pytest.raises(ValueError, match="Unrecognized format 'xml'"):
            _ = importer.import_text("<vault/>", "xml")

        mock_save.assert_not_called()

    @pytest.mark.parametrize("name", ["export.xml", "export", "export.json.bak"])
    def test_import_from_file_rejects_unknown_suffix(
        self, importer: Importer, mock_save: MagicMock, tmp_path: Path, name: str
    ) -> None:
        path = tmp_path / name
        _ = path.write_text(CONTENT_BY_FORMAT["json"])

        with pytest.raises(ValueError, match="Unrecognized format"):
            _ = importer.import_from_file(str(path))

        mock_save.assert_not_called()

    @pytest.mark.parametrize(
        "content", [json.dumps(["not", "a", "dict"]), json.dumps({"a": "b"}), "{"]
    )
    def test_import_text_rejects_malformed_json(
        self, importer: Importer, mock_save: MagicMock, content: str
    ) -> None:
        with pytest.raises(ImportFormatError, match="Invalid JSON export"):
            _ = importer.import_text(content, "json")

        mock_save.assert_not_called()

    def test_import_text_malformed_json_error_never_echoes_password(
        self,
        importer: Importer,
        mock_save: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The error reaches users and logs, so the plaintext password in the
        rejected content must appear in neither -- nor in a chained cause."""
        secret = "hunter2-SECRET"
        content = json.dumps({"github.com": {"login": "me", "password": 42}}).replace(
            "42", f'["{secret}"]'
        )

        with (
            caplog.at_level(logging.DEBUG, logger="passlair.share.importer"),
            pytest.raises(ImportFormatError) as exc_info,
        ):
            _ = importer.import_text(content, "json")

        assert secret not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__
        assert secret not in caplog.text

    @pytest.mark.parametrize(
        "fmt, content",
        [
            # missing space before "password=" -- a typo, not garbage
            ("txt", "service=github.com / login=me /password=hunter2-SECRET\n"),
            # a dropped column shifts the password into "login"
            ("csv", "service,login,password\r\ngithub.com,hunter2-SECRET\r\n"),
        ],
    )
    def test_skipped_entries_never_log_their_content(
        self,
        importer: Importer,
        mock_save: MagicMock,
        caplog: pytest.LogCaptureFixture,
        fmt: str,
        content: str,
    ) -> None:
        """A rejected line is usually a real credential with a typo; logs
        are plaintext and long-lived, so only its location may appear."""
        with caplog.at_level(logging.DEBUG, logger="passlair.share.importer"):
            result = importer.import_text(content, fmt)

        assert result == ImportResult(imported=0, skipped=1)
        assert "hunter2-SECRET" not in caplog.text

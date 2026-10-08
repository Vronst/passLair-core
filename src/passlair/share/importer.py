import csv
import io
import logging
from typing import override

import pyperclip
from pydantic import TypeAdapter, ValidationError

from ..base.abstract.authenticated_user import AuthenticatedUser
from ..base.abstract.base_importer import BaseImporter
from ..core.writers.password_writer import PasswordWriter
from ..dataclasses.import_result import ImportResult
from .formats import CSV_COLUMNS, TXT_PATTERN, format_from_path, require_format

logger = logging.getLogger(__name__)

_PASSWORDS_ADAPTER = TypeAdapter(dict[str, dict[str, str]])

type _Parsed = tuple[dict[str, dict[str, str]], int]


class ImportFormatError(ValueError):
    """The content doesn't match the format it was imported as.

    The message is safe to show a user: it never echoes the content, which
    holds plaintext passwords.
    """


class Importer(BaseImporter):
    def __init__(self, manager: AuthenticatedUser) -> None:
        self.__manager = manager

    @override
    def import_text(self, content: str, fmt: str) -> ImportResult:
        """Parses content as fmt ('txt'|'json'|'csv') and saves the entries.

        The single path that writes to the vault -- file and clipboard
        imports only fetch the text and delegate here.

        Raises ValueError for an unrecognized fmt, and ImportFormatError (a
        ValueError) for JSON that isn't {service: {login, password}}.
        """
        data, skipped = self._parse(content, fmt)
        self._save_passwords(data)
        logger.info(
            "import_text: imported %d entries as %s, skipped %d",
            len(data),
            fmt,
            skipped,
        )
        return ImportResult(imported=len(data), skipped=skipped)

    def import_from_clipboard(self, fmt: str) -> ImportResult:
        logger.info("import_from_clipboard: importing clipboard as %s", fmt)
        return self.import_text(pyperclip.paste(), fmt)

    def import_from_file(self, path: str, fmt: str | None = None) -> ImportResult:
        """Imports the file at path; fmt defaults to the file's suffix."""
        if fmt is None:
            fmt = format_from_path(path)

        logger.info("import_from_file: importing %r as %s", path, fmt)
        # newline="" so CSV quoted fields keep their embedded line endings;
        # splitlines() in _parse_txt and the JSON parser handle \r\n anyway.
        with open(path, encoding="utf-8", newline="") as file:
            content = file.read()

        return self.import_text(content, fmt)

    def _parse(self, content: str, fmt: str) -> _Parsed:
        require_format(fmt)
        match fmt:
            case "json":
                return self._parse_json(content)
            case "txt":
                return self._parse_txt(content)
            case _:
                return self._parse_csv(content)

    def _save_passwords(self, data: dict[str, dict[str, str]]) -> None:
        """Hands parsed {service: {"login": ..., "password": ...}} entries
        off to PasswordWriter, regardless of source format."""
        if not data:
            logger.warning("_save_passwords: no entries to import")
            return

        writer = PasswordWriter(self.__manager)
        writer.save_passwords(data)
        logger.debug("_save_passwords: handed %d entries to PasswordWriter", len(data))

    def _parse_json(self, content: str) -> _Parsed:
        try:
            return _PASSWORDS_ADAPTER.validate_json(content), 0
        except ValidationError as err:
            # include_input=False: pydantic's default str(err) and
            # traceback quote the offending values -- plaintext passwords.
            # Chained "from None" for the same reason; the locations logged
            # here are enough to debug a malformed export.
            locations = [e["loc"] for e in err.errors(include_input=False)]
            logger.warning(
                "_parse_json: %d validation error(s) at %s",
                err.error_count(),
                locations,
            )
            raise ImportFormatError(
                'Invalid JSON export: expected {"service": '
                + '{"login": "...", "password": "..."}}.'
            ) from None

    def _parse_txt(self, content: str) -> _Parsed:
        result: dict[str, dict[str, str]] = {}
        skipped = 0
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue

            match = TXT_PATTERN.fullmatch(line)
            if match is None:
                # Line number only: an unparsable line is usually a real
                # credential with a typo, so its text holds a plaintext password.
                logger.warning("_parse_txt: skipping unparsable line %d", line_number)
                skipped += 1
                continue

            fields = match.groupdict()
            service = fields.pop("service")
            result[service] = fields

        if skipped:
            logger.warning("_parse_txt: skipped %d unparsable line(s)", skipped)

        return result, skipped

    def _parse_csv(self, content: str) -> _Parsed:
        data: dict[str, dict[str, str]] = {}
        skipped = 0
        # StringIO(newline=""), not str.split("\n"): a quoted field may
        # legitimately contain a newline (csv.DictWriter quotes it on export),
        # and splitting first would silently glue it back without one.
        reader = csv.DictReader(io.StringIO(content, newline=""))
        # start=2: DictReader consumes the header as row 1 without
        # yielding it, so the first data row is physically line 2.
        for row_number, row in enumerate(reader, start=2):
            service = row.get("service")
            login = row.get("login")
            password = row.get("password")
            if service is None or login is None or password is None:
                # Column names, never the row: its values are plaintext
                # credentials, possibly shifted into the wrong column.
                missing = [name for name in CSV_COLUMNS if row.get(name) is None]
                logger.warning(
                    "_parse_csv: skipping malformed row %d, missing %s",
                    row_number,
                    missing,
                )
                skipped += 1
                continue

            data[service] = {"login": login, "password": password}

        if skipped:
            logger.warning("_parse_csv: skipped %d malformed row(s)", skipped)

        return data, skipped

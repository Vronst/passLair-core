import csv
import logging
import re
from typing import override

import pyperclip
from pydantic import TypeAdapter

from ..base.abstract.base_importer import BaseImporter
from ..core.auth.user_manager import UserManager
from ..core.writers.password_writer import PasswordWriter

logger = logging.getLogger(__name__)

_PASSWORDS_ADAPTER = TypeAdapter(dict[str, dict[str, str]])

# Matches one line in the format Exporter._export_txt writes:
# "service=<name> / login=<login> / password=<password>". `.+?`/`.+`
# (not `\w+`) so values may contain any character except a literal
# newline. Matched with fullmatch() against one line at a time (see
# _parse_txt), so this doesn't need its own start/end anchors.
_TXT_PATTERN = re.compile(
    r"service=(?P<service>.+?) / login=(?P<login>.+?) / password=(?P<password>.+)"
)


class Importer(BaseImporter):
    def __init__(self, manager: UserManager) -> None:
        self.__manager = manager

    @override
    def import_from_file(self, path: str, fmt: str) -> None:
        logger.info("import_from_file: importing %r as %s", path, fmt)
        match fmt:
            case "txt":
                self.import_from_txt(path)
            case "json":
                self.import_from_json(path)
            case "csv":
                self.import_from_csv(path)
            case _:
                logger.error("import_from_file: invalid format %r", fmt)
                raise ValueError("Invalid format. Choose txt/json/csv")

    def _save_passwords(self, data: dict[str, dict[str, str]]) -> None:
        """Hands parsed {service: {"login": ..., "password": ...}} entries
        off to PasswordWriter -- shared by every import_from_*/import_*_from_clipboard
        method regardless of source format."""
        if not data:
            logger.warning("_save_passwords: no entries to import")
            return

        writer = PasswordWriter(self.__manager)
        writer.save_passwords(data)
        logger.debug("_save_passwords: handed %d entries to PasswordWriter", len(data))

    def _parse_txt(self, content: str) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        skipped = 0
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue

            match = _TXT_PATTERN.fullmatch(line)
            if match is None:
                logger.warning(
                    "_parse_txt: skipping unparsable line %d: %r", line_number, line
                )
                skipped += 1
                continue

            fields = match.groupdict()
            service = fields.pop("service")
            result[service] = fields

        if skipped:
            logger.warning("_parse_txt: skipped %d unparsable line(s)", skipped)

        return result

    def import_from_json(self, path: str) -> None:
        with open(path) as file:
            data = _PASSWORDS_ADAPTER.validate_json(file.read())

        logger.debug("import_from_json: parsed %d entries from %r", len(data), path)
        self._save_passwords(data)

    def import_from_txt(self, path: str) -> None:
        with open(path) as file:
            data = self._parse_txt(file.read())

        logger.debug("import_from_txt: parsed %d entries from %r", len(data), path)
        self._save_passwords(data)

    def import_from_csv(self, path: str) -> None:
        data: dict[str, dict[str, str]] = {}
        skipped = 0
        with open(path, newline="") as file:
            # start=2: DictReader consumes the header as row 1 without
            # yielding it, so the first data row is physically line 2.
            for row_number, row in enumerate(csv.DictReader(file), start=2):
                service = row.get("service")
                login = row.get("login")
                password = row.get("password")
                if service is None or login is None or password is None:
                    logger.warning(
                        "import_from_csv: skipping malformed row %d: %r",
                        row_number,
                        row,
                    )
                    skipped += 1
                    continue

                data[service] = {"login": login, "password": password}

        if skipped:
            logger.warning("import_from_csv: skipped %d malformed row(s)", skipped)

        logger.debug("import_from_csv: parsed %d entries from %r", len(data), path)
        self._save_passwords(data)

    def import_txt_from_clipboard(self) -> None:
        clip = pyperclip.paste()
        data = self._parse_txt(clip)

        logger.debug(
            "import_txt_from_clipboard: parsed %d entries from clipboard", len(data)
        )
        self._save_passwords(data)

    def import_json_from_clipboard(self) -> None:
        clip = pyperclip.paste()
        data = _PASSWORDS_ADAPTER.validate_json(clip)

        logger.debug(
            "import_json_from_clipboard: parsed %d entries from clipboard", len(data)
        )
        self._save_passwords(data)

    @override
    def import_from_clipboard(self, fmt: str) -> None:
        logger.info("import_from_clipboard: importing clipboard as %s", fmt)
        match fmt:
            case "txt":
                self.import_txt_from_clipboard()
            case "json":
                self.import_json_from_clipboard()
            case _:
                logger.error("import_from_clipboard: invalid format %r", fmt)
                raise ValueError("Invalid format. Choose txt/json")

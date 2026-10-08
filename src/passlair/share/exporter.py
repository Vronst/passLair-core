import csv
import io
import json
import logging
import os
from typing import override

import pyperclip

from ..base.abstract.authenticated_user import AuthenticatedUser
from ..base.abstract.base_exporter import BaseExporter
from ..core.readers.password_reader import PasswordReader
from .formats import CSV_COLUMNS, TXT_LINE, format_from_path, require_format

logger = logging.getLogger(__name__)

type _Passwords = dict[str, dict[str, str]]


def _owner_only(path: str, flags: int) -> int:
    """open() opener: a new export file is readable by its owner only (0600),
    not the umask default (usually 0644, world-readable) -- it holds
    plaintext passwords. An existing file keeps its mode."""
    return os.open(path, flags, 0o600)


def _has_line_break(value: str) -> bool:
    # The txt importer splits on splitlines(), which also breaks on \v, \f,
    # \x1c-\x1e, \x85,   and   -- not just \n and \r. Joining the
    # pieces drops exactly those characters, so any change means one was there.
    return "".join(value.splitlines()) != value


class Exporter(BaseExporter):
    def __init__(self, manager: AuthenticatedUser) -> None:
        self.__manager = manager

    @override
    def serialize(self, fmt: str) -> str:
        """The whole vault as text in fmt ('txt'|'json'|'csv').

        The single path that decrypts for export -- file and clipboard
        exports only deliver the returned text. Importer.import_text reads
        every format back unchanged, except txt, which can't hold a newline
        inside a value.

        Raises ValueError for an unrecognized fmt, before decrypting anything.
        """
        require_format(fmt)
        passwords = self._retrieve_passwords()
        match fmt:
            case "json":
                text = json.dumps(passwords)
            case "csv":
                text = self._to_csv(passwords)
            case _:
                text = self._to_txt(passwords)

        logger.info("serialize: exported %d entries as %s", len(passwords), fmt)
        return text

    def export_to_file(self, path: str, fmt: str | None = None) -> None:
        """Writes the export to path; fmt defaults to the file's suffix."""
        if fmt is None:
            fmt = format_from_path(path)
        text = self.serialize(fmt)
        # newline="" writes the text as-is, so CSV keeps its \r\n row endings
        # and the \n inside quoted values isn't translated on Windows.
        with open(path, "w", encoding="utf-8", newline="", opener=_owner_only) as file:
            _ = file.write(text)

        logger.info("export_to_file: wrote %s export to %r", fmt, path)

    def export_to_clipboard(self, fmt: str = "txt") -> None:
        pyperclip.copy(self.serialize(fmt))
        logger.info("export_to_clipboard: copied %s export", fmt)

    def _retrieve_passwords(self) -> _Passwords:
        """Returns {service: {"login": ..., "password": ...}} for every vault
        entry belonging to the logged-in user.

        Delegates to PasswordReader.get_all_decrypted() rather than
        re-deriving the same decrypt-every-entry logic here, so the two
        can't drift apart."""
        result = PasswordReader(self.__manager).get_all_decrypted()
        logger.debug(
            "_retrieve_passwords: decrypted %d entries for export", len(result)
        )
        return result

    @staticmethod
    def _to_csv(passwords: _Passwords) -> str:
        # csv.DictWriter, not manual string-joining -- a service/login/password
        # containing a comma, quote, or newline (routine for real passwords)
        # would otherwise produce corrupt, unparsable CSV.
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(
            {"service": service, **credentials}
            for service, credentials in passwords.items()
        )
        return buffer.getvalue()

    @staticmethod
    def _to_txt(passwords: _Passwords) -> str:
        """Raises ValueError if any value holds a line break: txt is one entry
        per line, so the entry would be split and lost on import."""
        for service, credentials in passwords.items():
            if any(_has_line_break(v) for v in (service, *credentials.values())):
                logger.warning("_to_txt: an entry holds a line break, refusing txt")
                raise ValueError(
                    "An entry contains a line break, which txt can't hold. "
                    "Export as json or csv instead."
                )

        return "".join(
            TXT_LINE.format(service=service, **credentials)
            for service, credentials in passwords.items()
        )

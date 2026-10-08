"""The export formats, defined once for both Exporter and Importer.

Each layout lives here next to its parser so what Exporter writes and what
Importer reads can't drift apart.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

FORMATS = ("txt", "json", "csv")

CSV_COLUMNS = ("service", "login", "password")

TXT_LINE = "service={service} / login={login} / password={password}\n"

# Parses one TXT_LINE. `.+?`/`.+` (not `\w+`) so values may contain any
# character except a literal newline. Matched with fullmatch() against one
# line at a time, so it doesn't need its own start/end anchors.
TXT_PATTERN = re.compile(
    r"service=(?P<service>.+?) / login=(?P<login>.+?) / password=(?P<password>.+)"
)


def require_format(fmt: str) -> None:
    """Raises ValueError unless fmt is one of FORMATS."""
    if fmt not in FORMATS:
        logger.error("require_format: unrecognized format %r", fmt)
        raise ValueError(f"Unrecognized format {fmt!r}. Choose {'/'.join(FORMATS)}.")


def format_from_path(path: str) -> str:
    """The format named by path's last suffix, e.g. 'vault.JSON' -> 'json'.

    Raises ValueError when the suffix isn't one of FORMATS.
    """
    fmt = Path(path).suffix.lower().removeprefix(".")
    require_format(fmt)
    return fmt

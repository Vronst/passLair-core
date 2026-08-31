"""Interpreting SQLAlchemy ``IntegrityError``s across the supported drivers.

Neither SQLAlchemy nor the DBAPI exposes a portable way to tell *what kind* of
constraint an ``IntegrityError`` violated, so this relies on the driver's
error text/code. Only two drivers are in play:

  * sqlite3 -> "UNIQUE constraint failed: standard_users.username"
  * pymysql -> (1062, "Duplicate entry '...' for key '...username'")

Kept out of any writer module so every repository that catches
``IntegrityError`` (user, vault, ...) can share it.
"""

from sqlalchemy.exc import IntegrityError

_MYSQL_ER_DUP_ENTRY = 1062


def is_unique_violation(exc: IntegrityError) -> bool:
    """True if `exc` is a uniqueness / duplicate-key violation, as opposed to
    a NOT NULL, foreign-key, or CHECK failure."""
    orig = exc.orig
    text = str(orig).lower()
    args = getattr(orig, "args", ()) or ()

    return (
        "unique constraint failed" in text
        or "duplicate entry" in text
        or (len(args) > 0 and args[0] == _MYSQL_ER_DUP_ENTRY)
    )


def violation_names(exc: IntegrityError, *candidates: str) -> str | None:
    """Returns the first of `candidates` that appears in the error text
    (case-insensitively), or None if none do -- e.g. a duplicate on a
    composite index or ``PRIMARY`` names no single column."""
    text = str(exc.orig).lower()
    return next((c for c in candidates if c.lower() in text), None)

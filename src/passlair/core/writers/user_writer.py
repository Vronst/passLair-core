import logging

from sqlalchemy.exc import IntegrityError

from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.abstract.base_repository import BaseRepository
from ...dataclasses.user_data import UserCreation
from ..auth.credentials import (
    backup_kek_from_phrase,
    hash_new_password,
    new_backup_kek,
    new_dek,
    unwrap_dek,
    verify_password,
    wrap_dek,
)
from ..database.database_manager import db
from ..models.standard_user import StandardUser

logger = logging.getLogger(__name__)


def _unique_violation_field(exc: IntegrityError) -> str | None:
    """Classifies an IntegrityError raised while inserting a StandardUser.

    Returns ``"username"`` / ``"email"`` for a uniqueness violation on that
    column, ``"unknown"`` for a uniqueness violation whose column can't be
    told apart, or ``None`` when the error is something else entirely (NOT
    NULL, foreign key, ...) and must not be reported as a duplicate.

    Substring matching rather than a portable error code because SQLAlchemy
    exposes neither -- but the shape differs only between the two supported
    drivers:
      * sqlite3 -> "UNIQUE constraint failed: standard_users.username"
      * pymysql -> (1062, "Duplicate entry '...' for key '...username'")
    """
    orig = exc.orig
    text = str(orig).lower()
    orig_args = getattr(orig, "args", ()) or ()

    is_unique = (
        "unique constraint failed" in text
        or "duplicate entry" in text
        or (len(orig_args) > 0 and orig_args[0] == 1062)  # MySQL ER_DUP_ENTRY
    )
    if not is_unique:
        return None

    if "username" in text:
        return "username"
    if "email" in text:
        return "email"
    return "unknown"


class UserWriter(BaseRepository):
    def __init__(self, user: AuthenticatedUser) -> None:
        self.user: AuthenticatedUser = AuthenticatedUser.require(user)

    def change_password(self, new_password: str, old_password: str) -> None:
        """
        Re-derives the KEK from the old password to decrypt the existing DEK,
        then re-encrypts that same DEK under a freshly derived KEK for the new
        password, so previously-stored vault entries stay decryptable.
        """
        if not (
            user := self._fetch_row(StandardUser, filters={"id": self.user.user_id})
        ):
            logger.warning("change_password: no user for id=%r", self.user.user_id)
            raise ValueError("User doesn't exists!")

        old_kek = verify_password(old_password, user.salt, user.master_password)
        if old_kek is None:
            logger.warning(
                "change_password: wrong old password for user_id=%r", user.id
            )
            raise ValueError("Old password incorrect.")

        dek = unwrap_dek(user.dek, user.dek_nonce, old_kek)

        salt, hashed_password, kek = hash_new_password(new_password)
        enc_dek, dek_nonce = wrap_dek(dek, kek)

        user.master_password = hashed_password
        user.salt = salt
        user.dek = enc_dek
        user.dek_nonce = dek_nonce

        with db.session() as session:
            session.add(user)
            session.commit()

        logger.info("Password changed for user_id=%r", user.id)

    def reset_password(
        self, username: str, new_password: str, backup_phrase: str
    ) -> str:
        """
        Recovers the DEK using the one-time backup KEK phrase (there's no
        active session to derive one from, since the caller has forgotten
        their password), re-wraps it under a freshly derived KEK for the new
        password, and rotates the backup KEK so the phrase the user already
        has stops working.

        Returns the new backup phrase so it can be shown to the user exactly
        once.
        """
        if not (user := self._fetch_row(StandardUser, filters={"username": username})):
            logger.warning("reset_password: no user for username=%r", username)
            raise ValueError("User doesn't exists!")

        backup_kek = backup_kek_from_phrase(backup_phrase)
        dek = unwrap_dek(user.backup_dek, user.backup_dek_nonce, backup_kek)

        salt, hashed_password, kek = hash_new_password(new_password)
        enc_dek, dek_nonce = wrap_dek(dek, kek)

        new_kek, new_phrase = new_backup_kek()
        backup_dek, backup_dek_nonce = wrap_dek(dek, new_kek)

        user.master_password = hashed_password
        user.salt = salt
        user.dek = enc_dek
        user.dek_nonce = dek_nonce
        user.backup_dek = backup_dek
        user.backup_dek_nonce = backup_dek_nonce

        with db.session() as session:
            session.add(user)
            session.commit()

        logger.info("Password reset via backup phrase for user_id=%r", user.id)
        return new_phrase

    @classmethod
    def prepare_new_user(
        cls, username: str, email: str, password: str
    ) -> tuple[UserCreation, str]:
        """
        Generates a fresh salt/DEK pair and hashes the password for a new
        account. Also generates a random backup KEK and wraps the same DEK
        under it, so the user can recover access via reset_password without
        the backup KEK ever being stored. Returns the prepared user data
        together with the backup phrase, which the caller must show the user
        exactly once.
        """
        logger.debug("Preparing new user data for username=%r", username)
        salt, hashed_password, kek = hash_new_password(password)
        dek = new_dek()
        encrypted_dek, dek_nonce = wrap_dek(dek, kek)

        backup_kek, backup_phrase = new_backup_kek()
        backup_dek, backup_dek_nonce = wrap_dek(dek, backup_kek)

        data = UserCreation(
            username=username,
            email=email,
            master_password=hashed_password,
            salt=salt,
            dek=encrypted_dek,
            dek_nonce=dek_nonce,
            backup_dek=backup_dek,
            backup_dek_nonce=backup_dek_nonce,
        )
        return data, backup_phrase

    @classmethod
    def save_user(cls, data: UserCreation) -> None:
        """
        Attempts to write the user directly to the database.
        Catches database integrity constraints to bubble up clean errors.

        Args:
            data (UserCreation): The user data to save.
        """
        entry = StandardUser(**data.model_dump())

        try:
            with db.session() as session:
                session.add(entry)
                session.commit()
        except IntegrityError as e:
            field = _unique_violation_field(e)

            if field == "username":
                logger.warning(
                    "save_user rejected: username=%r already exists", data.username
                )
                raise ValueError("Username already exists") from e
            if field == "email":
                logger.warning(
                    "save_user rejected: email already in use for username=%r",
                    data.username,
                )
                raise ValueError("Email already exists") from e
            if field == "unknown":
                logger.warning(
                    "save_user rejected: uniqueness violation on an undetermined column"
                )
                raise ValueError("Username or email already exists") from e

            # Not a uniqueness violation -- don't mislabel it as a duplicate.
            logger.exception("save_user failed with an unexpected integrity error.")
            raise ValueError(
                "User could not be saved due to a database constraint."
            ) from e

        logger.info("User %r saved.", data.username)

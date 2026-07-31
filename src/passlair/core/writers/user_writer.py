import logging

from sqlalchemy.exc import IntegrityError

from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.base_repository import BaseRepository
from ...dataclasses.user_data import UserCreation
from ..auth.credentials import hash_password, new_dek, new_salt, unwrap_dek, verify_password, wrap_dek
from ..database.database_manager import db
from ..models.standard_user import StandardUser

logger = logging.getLogger(__name__)


class UserWriter(BaseRepository):
    def __init__(self, user: AuthenticatedUser) -> None:
        self.user = AuthenticatedUser.require(user)

    def change_password(self, new_password: str, old_password: str) -> None:
        """
        Re-derives the KEK from the old password to decrypt the existing DEK,
        then re-encrypts that same DEK under a freshly derived KEK for the new
        password, so previously-stored vault entries stay decryptable.
        """
        if not (user := self._fetch_row(StandardUser, filters={"id": self.user.user_id})):
            logger.warning("change_password: no user for id=%r", self.user.user_id)
            raise ValueError("User doesn't exists!")

        old_kek = verify_password(old_password, user.salt, user.master_password)
        if old_kek is None:
            logger.warning("change_password: wrong old password for user_id=%r", user.id)
            raise ValueError("Old password incorrect.")

        dek = unwrap_dek(user.dek, user.dek_nonce, old_kek)

        salt = new_salt()
        hashed_password, kek = hash_password(new_password, salt)
        enc_dek, dek_nonce = wrap_dek(dek, kek)

        user.master_password = hashed_password
        user.salt = salt
        user.dek = enc_dek
        user.dek_nonce = dek_nonce

        with db.session() as session:
            session.add(user)
            session.commit()

        logger.info("Password changed for user_id=%r", user.id)

    def reset_password(self, username: str) -> None:
        # TODO: reseting password with email?
        pass

    @classmethod
    def prepare_new_user(cls, username: str, email: str, password: str) -> UserCreation:
        """Generates a fresh salt/DEK pair and hashes the password for a new account."""
        logger.debug("Preparing new user data for username=%r", username)
        salt = new_salt()
        hashed_password, kek = hash_password(password, salt)
        encrypted_dek, dek_nonce = wrap_dek(new_dek(), kek)

        return UserCreation(
            username=username,
            email=email,
            master_password=hashed_password,
            salt=salt,
            dek=encrypted_dek,
            dek_nonce=dek_nonce,
        )

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
            error_msg = str(e.orig).lower()

            if "username" in error_msg:
                logger.warning("save_user rejected: username=%r already exists", data.username)
                raise ValueError("Username already exists")
            elif "email" in error_msg:
                logger.warning("save_user rejected: email already in use for username=%r", data.username)
                raise ValueError("Email already exists")

            logger.exception("save_user failed with an unexpected integrity error.")
            raise ValueError("User registration failed: Duplication error.")

        logger.info("User %r saved.", data.username)

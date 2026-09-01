from typing import override
import logging

from ...base.abstract.authenticated_user import AuthenticatedUser
from ..models.standard_user import StandardUser
from ..readers.user_reader import UserReader
from .credentials import unwrap_dek, verify_password

logger = logging.getLogger(__name__)


class UserManager(AuthenticatedUser):
    def __init__(self) -> None:
        self.__dek: bytes | None = None
        self.__user_id: str | None = None

    @property
    @override
    def user_id(self) -> str | None:
        return self.__user_id

    @property
    def login_status(self) -> bool:
        if self.__dek and self.__user_id:
            return True
        return False

    def login(self, username: str, password: str) -> bool:
        """
        Validates user credentials and sets up the temporary session key.
        """
        if self.user_id is not None:
            logger.warning(
                "login: rejected, session already active for user_id=%r",
                self.user_id,
            )
            raise RuntimeError("User already logged in!")

        if result := self._verify_password(username, password):
            user, kek = result
            dek = unwrap_dek(user.dek, user.dek_nonce, kek)
            self.__user_id = user.id
            self.__dek = dek
            logger.info(
                "login: username=%r authenticated as user_id=%r", username, user.id
            )
            return True

        logger.warning("login: failed attempt for username=%r", username)
        return False

    def _verify_password(
        self, username: str, password: str
    ) -> tuple[StandardUser, bytes] | None:
        """
        Looks up the user and validates the supplied password.

        Returns the user row together with its derived KEK (instead of
        re-deriving it in `login`) so the DEK can be decrypted without
        running the expensive KDF twice.
        """
        user = UserReader.get_user_by_name(username)
        if not user:
            logger.debug("_verify_password: no user for username=%r", username)
            return None

        kek = verify_password(password, user.salt, user.master_password)
        if kek is None:
            logger.debug(
                "_verify_password: password hash mismatch for username=%r", username
            )
            return None

        return user, kek

    def logout(self) -> None:
        if not self.__dek or not self.user_id:
            logger.warning("logout: attempted with no active session")
            raise RuntimeError("Tried login out when not loged.")

        logger.info("logout: user_id=%r logged out", self.__user_id)
        self.__dek = None
        self.__user_id = None

    @override
    def get_session_key(self) -> bytes:
        """Returns the DEK for the short duration of a vault decryption action."""
        if not self.__dek:
            logger.warning("get_session_key: called with no active session")
            raise PermissionError("No active secure session. Please log in.")
        return self.__dek

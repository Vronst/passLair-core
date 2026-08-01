"""Facade for easier interacting with authentication."""

import logging
from typing import TYPE_CHECKING

from ..readers.helpers import compare_passwords
from ...base.abstract.base_facade import BaseFacade
from ..auth.user_manager import UserManager
from ..writers.user_writer import UserWriter

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from ...dataclasses.facade_result import FacadeResult


class Identity(BaseFacade):
    def __init__(
        self,
        user_manager: UserManager | None = None,
        user_writer: UserWriter | None = None,
    ):
        self.manager = user_manager or UserManager()
        self.user_writer = user_writer or UserWriter(self.manager)

    @property
    def login_status(self) -> FacadeResult:
        if self.manager.login_status:
            return self._success("User loged in.", {"user_id": self.manager.user_id})

        return self._failure("User not loged in.")

    def login(self, username: str, password: str) -> FacadeResult:
        try:
            if self.manager.login(username, password):
                return self._success("Successfully loged in.")

            return self._failure("Username or password incorrect.")
        except RuntimeError as e:
            logger.warning("Identity.login rejected: %s", e)
            return self._failure(str(e))

    def logout(self) -> FacadeResult:
        try:
            self.manager.logout()
        except RuntimeError as e:
            logger.warning("Identity.logout rejected: %s", e)
            return self._failure(str(e))

        return self._success("Loged out.")

    def change_user_password(
        self, new_password: str, old_password: str
    ) -> FacadeResult:
        if not isinstance(old_password, str) or old_password == "":
            logger.warning(
                "change_user_password: old_password must be a non-empty string"
            )
            return self._failure("Old password must be a non-empty string.")
        if not self.manager.login_status:
            logger.warning("change_user_password attempted without an active session.")
            return self._failure("User not logged in.")

        assert self.manager.user_id
        if not compare_passwords(self.manager.user_id, old_password):
            logger.warning(
                "change_user_password rejected: wrong old password for user_id=%r",
                self.manager.user_id,
            )
            return self._failure("Old password incorrect.")

        try:
            self.user_writer.change_password(new_password, old_password)
        except ValueError as e:
            logger.warning(
                "change_user_password failed for user_id=%r: %s",
                self.manager.user_id,
                e,
            )
            return self._failure(str(e))

        logger.info("Password changed for user_id=%r", self.manager.user_id)
        return self._success("Password was changed")

    def reset_user_password(
        self, username: str, backup_phrase: str, new_password: str
    ) -> FacadeResult:
        try:
            new_phrase = self.user_writer.reset_password(
                username, new_password, backup_phrase
            )
        except ValueError as e:
            logger.warning(
                "reset_user_password failed for username=%r: %s", username, e
            )
            return self._failure(str(e))

        logger.info("Password reset via backup phrase for username=%r", username)
        return self._success("Password was reset.", {"backup_phrase": new_phrase})

    def register_user(self, login: str, email: str, password: str) -> FacadeResult:
        """
        Registers a new user by saving their data and logging them in.

        Args:
            login (str): The username of the new user.
            email (str): The email of the new user.
            password (str): The password of the new user.

        Returns:
            FacadeResult: A success or failure result indicating the outcome of the registration.
        """
        user, backup_phrase = self.user_writer.prepare_new_user(login, email, password)
        try:
            self.user_writer.save_user(user)
            self.manager.login(login, password)
            logger.info("User %r registered.", login)
            return self._success(
                "User registered successfully.", {"backup_phrase": backup_phrase}
            )
        except (ValueError, RuntimeError) as e:
            logger.warning("Registration failed for username=%r: %s", login, e)
            return self._failure(str(e))

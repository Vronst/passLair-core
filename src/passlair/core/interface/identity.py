"""Facade for easier interacting with authentication."""

from typing import TYPE_CHECKING

from ...dataclasses.user_data import UserCreation
from ...base.abstract.base_facade import BaseFacade
from ..auth.user_manager import UserManager
from ..readers.user_reader import UserReader
from ..writers.user_writer import UserWriter


if TYPE_CHECKING:
    from ...dataclasses.facade_result import FacadeResult


class Identity(BaseFacade):
    def __init__(self,
        user_manager: UserManager | None = None,
        user_writer: UserWriter | None = None
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
            return self._failure(str(e))

    def logout(self) -> FacadeResult:
        try:
            self.manager.logout()
        except RuntimeError as e:
            return self._failure(str(e))

        return self._success("Loged out.")

    def change_user_password(
        self, old_password: str, new_password: str
    ) -> FacadeResult:
        pass

    def reset_user_password(self, user_id: str) -> FacadeResult:
        pass

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
        user = UserCreation(username=login, email=email, master_password=password, salt='temp')
        try:
            self.user_writer.save_user(user)
            self.manager.login(login, password)
            return self._success("User registered successfully.")
        except ValueError as e:
            return self._failure(str(e))

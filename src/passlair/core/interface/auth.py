"""Facade for easier interacting with authentication."""

from typing import TYPE_CHECKING

from ...base.abstract.base_facade import BaseFacade
from ..auth.user_manager import UserManager

if TYPE_CHECKING:
    from ...dataclasses.facade_result import FacadeResult


class Authentication(BaseFacade):
    def __init__(self):
        self.manager = UserManager()

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

    def reset_user_password(self, new_password: str) -> FacadeResult:
        pass

    def register_user(self, login: str, password: str) -> FacadeResult:
        pass

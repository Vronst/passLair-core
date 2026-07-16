# This is core Facade, so this only wraps core functions, updating password etc should be in WEB or CLI
from ...dataclasses.facade_result import FacadeResult
from ...base.abstract.base_facade import BaseFacade
from ...base.abstract.authenticated_user import AuthenticatedUser
from ..readers.password_reader import PasswordReader
from ..writers.password_writer import PasswordWriter


class PasswordManager(BaseFacade):
    def __init__(self, auth: AuthenticatedUser):
        self.auth = auth
        self.pass_reader = PasswordReader(auth)
        self.pass_writer = PasswordWriter(auth)

    def get_password_for_service(self, service: str) -> FacadeResult:
        try:
            result = self.pass_reader.get_pass_for(service)
            return self._success("Password retrieved successfuly", result)

        except (KeyError, RuntimeError) as e:
            return self._failure(str(e))

    def set_password_for_service(self, service: str, login: str, password: str) -> FacadeResult:
        try:
            if not self.pass_writer.save_password(service, login, password):
                raise RuntimeError("Failed to save credentials")

            return self._success("Password set succesfully")

        except (KeyError, RuntimeError, ValueError, TypeError) as e:
            return self._failure(str(e))

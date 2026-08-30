# This is core Facade, so this only wraps core functions, updating password etc should be in WEB or CLI
from ...dataclasses.facade_result import FacadeResult
from ...base.abstract.base_facade import BaseFacade
from ...base.abstract.authenticated_user import AuthenticatedUser
from ..readers.password_reader import PasswordReader
from ..writers.password_writer import PasswordWriter


class PasswordManager(BaseFacade):
    def __init__(self, auth: AuthenticatedUser) -> None:
        self.auth: AuthenticatedUser = auth
        self.pass_reader: PasswordReader = PasswordReader(auth)
        self.pass_writer: PasswordWriter = PasswordWriter(auth)

    def get_password_for_service(self, service: str) -> FacadeResult:
        try:
            result = self.pass_reader.get_pass_for(service)
            return self._success("Password retrieved successfully", result)

        except (KeyError, RuntimeError, PermissionError) as e:
            return self._failure(str(e))

    def list_services(self) -> FacadeResult:
        """Service names of every stored credential for the logged-in user.
        Nothing is decrypted."""
        try:
            services = self.pass_reader.get_all_services()
            return self._success(
                "Services retrieved successfully", {"services": services}
            )

        except (RuntimeError, PermissionError) as e:
            return self._failure(str(e))

    def list_entries(self) -> FacadeResult:
        """Every stored credential for the logged-in user, decrypted, as
        ``{service: {"login": ..., "password": ...}}``."""
        try:
            entries = self.pass_reader.get_all_decrypted()
            return self._success("Entries retrieved successfully", {"entries": entries})

        except (RuntimeError, PermissionError) as e:
            return self._failure(str(e))

    def set_password_for_service(
        self, service: str, login: str, password: str
    ) -> FacadeResult:
        try:
            if not self.pass_writer.save_password(service, login, password):
                raise RuntimeError("Failed to save credentials")

            return self._success("Password set succesfully")

        except (KeyError, RuntimeError, ValueError, TypeError, PermissionError) as e:
            return self._failure(str(e))

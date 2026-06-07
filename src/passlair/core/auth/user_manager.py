from ...base.abstract.authenticated_user import AuthenticatedUser
from ..models.standard_user import StandardUser
from ..readers.user_reader import UserReader


class UserManager(AuthenticatedUser):
    def __init__(self):
        self.__dek: str | None = None
        self.__user_id: str | None = None

    @property
    def user_id(self) -> str | None:
        return self.__user_id

    def login(self, username: str, password: str) -> bool:
        """
        Validates user credentials and sets up the temporary session key.
        """
        if self.user_id is not None:
            raise RuntimeError("User already logged in!")

        if user := self._verify_password(username, password):
            self.__user_id = user.id
            self.__dek = ...  # TODO: get dek
            return True
        return False

    def _verify_password(self, username: str, password: str) -> StandardUser | None:
        user = UserReader.get_user_by_name(username)
        if not user:
            return
        encrypted_password: str = user.master_password_hash
        salt = user.encryption_salt
        decrypted_password = ...  # TODO: decryption
        decrypted_password = "some_password"  # FIXME: DElete
        print(password, decrypted_password)
        if password == decrypted_password:
            ...
            return user

    def logout(self) -> None:
        if not self.__dek or not self.user_id:
            raise RuntimeError("Tried login out when not loged.")

        self.__session = None
        self.__user_id = None

    def get_session_key(self) -> str:
        """Returns the DEK for the short duration of a vault decryption action."""
        if not self.__dek:
            raise PermissionError("No active secure session. Please log in.")
        return self.__dek

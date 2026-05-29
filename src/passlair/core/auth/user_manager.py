from ..models.standard_user import StandardUser
from ..readers.user_reader import UserReader


class UserManager:
    def __init__(self):
        self.__dek: str | None = None
        self.user_id: str | None = None

    def login(self, username: str, password: str) -> bool:
        """
        Validates user credentials and sets up the temporary session key.
        """
        if self.user_id is not None:
            raise RuntimeError("User already logged in!")

        if (user := self._verify_password(username, password)):
            self.user_id = user.id
            self.__dek = # TODO: get dek
            return True
        return False

    def _verify_password(self, username: str, password: str) -> StandardUser | None:
        user = UserReader.get_user_by_name(username)
        if not user:
            return
        encrypted_password: str = user.master_password_hash
        salt = user.encryption_salt
        # TODO: decryption
        if password == decrypted_password:
            ...
        return None

    def logout(self):
        if self.__session:
            for i in range(len(self.__session)):
                self.__session[i] = 0
            self.__session = None
        self.user_id = None

    def get_session_key(self) -> str:
        """Returns the DEK for the short duration of a vault decryption action."""
        if not self.__dek:
            raise PermissionError("No active secure session. Please log in.")
        return self.__dek

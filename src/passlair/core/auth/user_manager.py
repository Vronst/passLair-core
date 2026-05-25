from ...base.base_repository import BaseRepository
from ..database.database_manager import db
from ..models.standard_user import StandardUser


class UserManager:
    def __init__(self):
        self.__dek: bytearray | None = None
        self.user_id: bytearray | None = None

    def login(self, username: str, password_bytes: bytearray):
        """
        Validates user credentials and sets up the temporary session key.
        Takes password_bytes as a mutable bytearray so we can control its lifecycle.
        """
        # FIXME: override it to your lib
        pass

    def logout(self):
        if self.__session:
            for i in range(len(self.__session)):
                self.__session[i] = 0
            self.__session = None
        self.user_id = None

    def get_session_key(self) -> bytearray:
        """Returns the DEK for the short duration of a vault decryption action."""
        if not self.__dek:
            raise PermissionError("No active secure session. Please log in.")
        return self.__dek

    def
            input_auth_hash = TODO  # FIXME: hash inputed password
            if not TODO:  # FIXME: compare passwords
                return False

            # 4. Login successful! Derive the Data Encryption Key (DEK)
            # We use a slightly altered process so the login hash != encryption key
            raw_session = TODO  # FIXME: create session
            # Store the DEK as a mutable bytearray for decryption tasks later
            self._session_dek = bytearray(raw_session)
            self.current_user_id = user.id
            return True

        finally:
            if password_bytes:
                for i in range(len(password_bytes)):
                    password_bytes[i] = 0

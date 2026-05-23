from ..database.database_manager import db
from ..models import StandardUser


class UserManager:
    def __init__(self):
        self.__session: bytearray | None = None
        self.user_id: bytearray | None = None

    def login(self, username: str, password_bytes: bytearray):
        """
        Validates user credentials and sets up the temporary session key.
        Takes password_bytes as a mutable bytearray so we can control its lifecycle.
        """
        # FIXME: override it to your lib
        try:
            # 1. Fetch user record by username
            # (Assuming you use the SQLAlchemy User model from earlier)
            with db.session() as session:
                user = (
                    session.query(StandardUser)
                    .filter_by(master_username=username)
                    .first()
                )
            if not user:
                return False

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
        return False

    def logout(self):
        if self.__session:
            for i in range(len(self.__session)):
                self.__session[i] = 0
            self.__session = None
        self.user_id = None

    def get_session_key(self) -> bytearray:
        """Returns the DEK for the short duration of a vault decryption action."""
        if not self._session_dek:
            raise PermissionError("No active secure session. Please log in.")
        return self._session_dek

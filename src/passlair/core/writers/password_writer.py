import os

from ...base.base_repository import BaseRepository
from ..auth.user_manager import UserManager
from ..database.database_manager import db
from ..models.vault_entry import VaultEntry


class PasswordSaver(BaseRepository):
    def __init__(self, user: UserManager):
        self.user = user

    def save_password(self, service: str, login: str, password: str) -> bool:
        if (dek := self.user.get_session_key()) is None:
            raise ValueError("User session expired")

        encrypted_password, nonce = self._encrypt_password(password, dek)
        data = {
            "service": service,
            "login": login,
            "password": password,
            "encrypted_password": encrypted_password,
        }
        if not (entry := self._add_or_update(data)):
            return False
        with db.session() as session:
            session.add(entry)
            session.commit()

        return True

    def _add_or_update(self, data: dict) -> VaultEntry:
        entry = self._fetch_row(
            VaultEntry,
            filters={"service": data["service"], "user_id": self.user.user_id},
        )
        if entry is None:
            new_entry = self._new_password(data)
        else:
            new_entry = self._update_password(data, entry)

        return new_entry

    def _update_password(self, data: dict, entry: VaultEntry) -> VaultEntry:
        encrypted_password, nonce = self._encrypt_password(
            data["password"], self.user.get_session_key()
        )
        entry.encrypted_password = encrypted_password
        entry.login = data["login"]
        entry.nonce = nonce
        return entry

    def _new_password(self, data) -> VaultEntry:
        new_pass = VaultEntry(
            user_id=self.user.user_id,
            service=data["service"],
            login=data["login"],
            nonce=data["nonce"],
            encrypted_password=data["encrypted_password"],
        )
        return new_pass

    def _encrypt_password(self, password: str, dek: str) -> tuple[bytearray, bytes]:
        nonce = os.urandom(12)
        encrypted_password = (
            # TODO  # FIXME: function crypting password with nonce and dek
        )
        return encrypted_password, nonce

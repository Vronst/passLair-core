import os

from ...base.base_repository import BaseRepository
from ...dataclasses.password_data import PasswordCreation
from ..auth.user_manager import UserManager
from ..database.database_manager import db
from ..models.vault_entry import VaultEntry


class PasswordWriter(BaseRepository):
    def __init__(self, user: UserManager):
        self.user = user

    def save_password(self, service: str, login: str, password: str) -> bool:
        data = self._prepare_data(service, login, password)
        if not (entry := self._add_or_update(data)):
            return False

        with db.session() as session:
            session.add(entry)
            session.commit()

        return True

    def _prepare_data(
        self, service: str, login: str, password: str
    ) -> PasswordCreation:
        if not self.user or (dek := self.user.get_session_key()) is None:
            raise ValueError("User session expired")

        encrypted_password, nonce = self._encrypt_password(password, dek)
        assert isinstance(self.user.user_id, str)  # for linting
        return PasswordCreation(
            user_id=self.user.user_id,
            service_name=service,
            login=login,
            encrypted_password=encrypted_password,
            nonce=nonce,
        )

    def _add_or_update(self, data: PasswordCreation) -> VaultEntry:
        entry = self._fetch_row(
            VaultEntry,
            filters={"service": data["service"], "user_id": self.user.user_id},
        )
        if entry is None:
            new_entry = self._new_password(data)
        else:
            new_entry = self._update_password(data, entry)

        return new_entry

    def _update_password(self, data: PasswordCreation, entry: VaultEntry) -> VaultEntry:
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
        encrypted_password = ...  # TODO: function crypting password with nonce and dek
        return encrypted_password, nonce

import os

from passlair_crypto.package import encrypt_password

from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.base_repository import BaseRepository
from ...dataclasses.password_data import PasswordCreation
from ..database.database_manager import db
from ..models.vault_entry import VaultEntry


class PasswordWriter(BaseRepository):
    def __init__(self, user: AuthenticatedUser):
        if not isinstance(user, AuthenticatedUser):
            raise TypeError("Invalid UserManager argument on init.")
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

        if service == '' or login == '' or password == '':
            raise ValueError("Service name, login and password must not be empty")

        encrypted_password, nonce = self._encrypt_password(password, dek)
        assert isinstance(self.user.user_id, str)  # for linting
        return PasswordCreation(
            user_id=self.user.user_id,
            service_name=service,
            login=login,
            password=encrypted_password,
            nonce=nonce,
        )

    def _add_or_update(self, data: PasswordCreation) -> VaultEntry:
        entry = self._fetch_row(
            VaultEntry,
            filters={"service": data["service_name"], "user_id": self.user.user_id},
        )
        if entry is None:
            new_entry = self._new_password(data)
        else:
            new_entry = self._update_password(data, entry)

        return new_entry

    def _update_password(self, data: PasswordCreation, entry: VaultEntry) -> VaultEntry:
        entry.password = data["password"]
        entry.login = data["login"]
        entry.nonce = data["nonce"]
        return entry

    def _new_password(self, data: PasswordCreation) -> VaultEntry:
        new_pass = VaultEntry(**data.model_dump())
        return new_pass

    def _encrypt_password(self, password: str, dek: str) -> tuple[str, bytes]:
        if not isinstance(dek, str) or dek == "":
            raise ValueError("Session key is invalid!")
        nonce = os.urandom(12)
        encrypted_password = encrypt_password(password.encode("utf-8"), nonce, dek.encode("utf-8"))
        return encrypted_password.decode("utf-8"), nonce

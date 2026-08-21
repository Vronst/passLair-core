import logging

from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.base_repository import BaseRepository
from ...dataclasses.password_data import PasswordCreation
from ..crypto import encrypt
from ..database.database_manager import db
from ..models.vault_entry import VaultEntry

logger = logging.getLogger(__name__)


class PasswordWriter(BaseRepository):
    def __init__(self, user: AuthenticatedUser) -> None:
        self.user: AuthenticatedUser = AuthenticatedUser.require(user)

    def save_password(self, service: str, login: str, password: str) -> bool:
        data = self._prepare_data(service, login, password)
        entry = self._add_or_update(data)

        with db.session() as session:
            session.add(entry)
            session.commit()

        logger.info(
            "Password saved for service=%r, user_id=%r", service, self.user.user_id
        )
        return True

    def _prepare_data(
        self, service: str, login: str, password: str
    ) -> PasswordCreation:
        # get_session_key() raises PermissionError itself when there's no
        # active session -- it never returns None, so callers must catch
        # PermissionError rather than expect a ValueError here.
        dek = self.user.get_session_key()

        if service == "" or login == "" or password == "":
            logger.warning("_prepare_data rejected empty service/login/password field.")
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
            filters={
                "service_name": data.service_name,
                "user_id": self.user.user_id,
            },
        )
        if entry is None:
            new_entry = self._new_password(data)
        else:
            new_entry = self._update_password(data, entry)

        return new_entry

    def _update_password(self, data: PasswordCreation, entry: VaultEntry) -> VaultEntry:
        entry.password = data.password
        entry.login = data.login
        entry.nonce = data.nonce
        return entry

    def _new_password(self, data: PasswordCreation) -> VaultEntry:
        new_pass = VaultEntry(**data.model_dump())
        return new_pass

    def _encrypt_password(self, password: str, dek: bytes) -> tuple[bytes, bytes]:
        return encrypt(password.encode("utf-8"), dek)

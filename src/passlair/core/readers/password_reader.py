from ...base.base_repository import BaseRepository
from ..auth.user_manager import UserManager
from ..models.vault_entry import VaultEntry


class PasswordReader(BaseRepository):
    def __init__(self, user: UserManager):
        self.user = user

    def get_pass_for(self, service: str) -> dict:
        encrypted_password = self._retrieve_password(service)
        if encrypted_password is None:
            raise KeyError("Password for this service not found")

        return self._decrypt_password(encrypted_password, self.user.get_session_key())

    def _decrypt_password(self, vault: VaultEntry, dek: bytearray) -> dict:
        encrypted_password = vault.encrypted_password
        nounce = vault.nonce
        login = vault.login

        TODO  # FIXME: Decrypt password with DEK and nounce

        return {"login": login, "password": password}

    def _retrieve_password(self, service) -> VaultEntry | None:
        password = self._fetch_row(
            VaultEntry, filters={"service": service, "user_id": self.user.user_id}
        )

        return password

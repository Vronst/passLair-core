import logging


from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.base_repository import BaseRepository
from ..crypto import decrypt
from ..models.vault_entry import VaultEntry

logger = logging.getLogger(__name__)


class PasswordReader(BaseRepository):
    def __init__(self, user: AuthenticatedUser) -> None:
        self.user: AuthenticatedUser = AuthenticatedUser.require(user)

    def get_pass_for(self, service: str) -> dict[str, str]:
        encrypted_password = self._retrieve_password(service)
        if encrypted_password is None:
            logger.warning("get_pass_for: no vault entry for service=%r", service)
            raise KeyError("Password for this service not found")

        logger.debug("Decrypting vault entry for service=%r", service)
        return self._decrypt_password(encrypted_password, self.user.get_session_key())

    def _decrypt_password(self, vault: VaultEntry, dek: bytes) -> dict[str, str]:
        encrypted_password = vault.password
        nonce = vault.nonce
        login = vault.login
        decrypted_password = decrypt(encrypted_password, nonce, dek)
        return {"login": login, "password": decrypted_password.decode("utf-8")}

    def _retrieve_password(self, service: str) -> VaultEntry | None:
        password = self._fetch_row(
            VaultEntry, filters={"service_name": service, "user_id": self.user.user_id}
        )

        return password

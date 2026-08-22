import logging


from ...base.abstract.authenticated_user import AuthenticatedUser
from ...base.base_repository import BaseRepository
from ..database.database_manager import db
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

    def get_all_passwords(self) -> list[VaultEntry]:
        """Returns every vault entry belonging to the logged-in user, still encrypted.

        Raises PermissionError if there's no active session. An authenticated
        user with an empty vault gets back [] -- that's a normal state, not
        a failure to be conflated with "not logged in".
        """
        # get_session_key() raises PermissionError itself when there's no
        # active session -- calling it here is what lets an empty vault and
        # "not logged in" be told apart, since both would otherwise produce
        # the same empty query result below.
        _ = self.user.get_session_key()

        with db.session() as session:
            result = (
                session.query(VaultEntry).filter_by(user_id=self.user.user_id).all()
            )

        logger.debug(
            "get_all_passwords: found %d entries for user_id=%r",
            len(result),
            self.user.user_id,
        )
        return result

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

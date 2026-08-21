from passlair.core.auth.user_manager import UserManager
from passlair.core.interface.password_manager import PasswordManager


class TestPositive:
    def test_get_password_for_service_round_trips_through_real_crypto(
        self,
        user_manager_with_passwords: tuple[UserManager, list[dict[str, str]]],
    ) -> None:
        """
        No unit test exercises PasswordReader against real ChaCha20-Poly1305
        decryption (they mock the crypto boundary, on purpose) -- this is the
        one place a password saved through the real encrypt path is read back
        and proven to decrypt to the exact plaintext that was written.
        """
        user_manager, passwords = user_manager_with_passwords
        manager = PasswordManager(user_manager)

        for credentials in passwords:
            result = manager.get_password_for_service(credentials["service"])

            assert result.success
            assert result.data["login"] == credentials["login"]
            assert result.data["password"] == credentials["password"]

    def test_set_password_for_service_persists_and_is_retrievable(
        self, register_user: dict[str, str]
    ) -> None:
        user_manager = UserManager()
        assert user_manager.login(register_user["username"], register_user["password"])
        manager = PasswordManager(user_manager)

        assert manager.set_password_for_service(
            "new_service", "new_login", "new_secret"
        ).success

        result = manager.get_password_for_service("new_service")
        assert result.success
        assert result.data == {"login": "new_login", "password": "new_secret"}


class TestNegative:
    def test_get_password_for_service_missing_service(
        self, register_user: dict[str, str]
    ) -> None:
        user_manager = UserManager()
        assert user_manager.login(register_user["username"], register_user["password"])
        manager = PasswordManager(user_manager)

        result = manager.get_password_for_service("does-not-exist")

        assert not result.success

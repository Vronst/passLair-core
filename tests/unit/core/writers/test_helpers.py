from passlair.core.models import VaultEntry
from passlair.core.writers.helpers import check_if_entry_in_list, compare_vault_entries

base_entry = VaultEntry(
    user_id="user-1",
    service_name="github.com",
    login="my_login",
    password=b"ciphertext-a",
    nonce=b"nonce-a-1234",
)


def make_entry(**overrides: object) -> VaultEntry:
    data = {
        "user_id": "user-1",
        "service_name": "github.com",
        "login": "my_login",
        "password": b"ciphertext-a",
        "nonce": b"nonce-a-1234",
    }
    data.update(overrides)
    return VaultEntry(**data)  # type: ignore[arg-type]


class TestPositive:
    def test_compare_vault_entries_true_for_matching_service_login_password(
        self,
    ) -> None:
        other = make_entry()

        assert compare_vault_entries(base_entry, other) is True

    def test_check_if_entry_in_list_true_when_a_match_is_present(self) -> None:
        entries = [make_entry(service_name="other.com"), make_entry()]

        assert check_if_entry_in_list(base_entry, entries) is True


class TestNegative:
    def test_compare_vault_entries_false_when_service_differs(self) -> None:
        other = make_entry(service_name="gitlab.com")

        assert compare_vault_entries(base_entry, other) is False

    def test_compare_vault_entries_false_when_login_differs(self) -> None:
        other = make_entry(login="someone_else")

        assert compare_vault_entries(base_entry, other) is False

    def test_compare_vault_entries_false_when_ciphertext_differs(self) -> None:
        """Documents a real limitation: encryption uses a fresh nonce every call
        (see core.crypto.encrypt), so re-encrypting the exact same plaintext
        password never reproduces the same ciphertext. Comparing on
        `password` therefore cannot detect "same plaintext, re-imported" --
        only byte-for-byte identical ciphertext, which two independent
        encryptions will essentially never produce. See PasswordWriter's
        save_passwords tests for the practical impact of this.
        """
        other = make_entry(password=b"ciphertext-b")

        assert compare_vault_entries(base_entry, other) is False

    def test_check_if_entry_in_list_false_when_no_match(self) -> None:
        entries = [make_entry(service_name="other.com")]

        assert check_if_entry_in_list(base_entry, entries) is False

    def test_check_if_entry_in_list_false_for_empty_list(self) -> None:
        assert check_if_entry_in_list(base_entry, []) is False

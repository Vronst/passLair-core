from passlair.core.models import VaultEntry


def compare_vault_entries(first: VaultEntry, other: VaultEntry) -> bool:
    return (
    first.service_name == other.service_name and
    first.login == other.login and
    first.password == other.password
    )

def check_if_entry_in_list(target: VaultEntry, entries: list[VaultEntry]) -> bool:
    for entry in entries:
        if compare_vault_entries(target, entry):
            return True

    return False

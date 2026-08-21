from ..core.auth.user_manager import UserManager


class Exporter:
    def __init__(self, manager: UserManager) -> None:
        self.__manager = manager

    def _retrieve_passwords(self) -> dict[str, dict[str, str]]:
        """Returns {service: {"login": ..., "password": ...}} for every vault
        entry belonging to the logged-in user."""
        pass

    def export_to_txt(self, path: str) -> None:
        pass

    def export_to_csv(self, path: str) -> None:
        pass

    def export_to_json(self, path: str) -> None:
        pass

    def export_to_file(self, path: str, fmt: str) -> None:
        """Dispatches to export_to_txt/csv/json based on fmt ('txt'|'csv'|'json').

        Raises ValueError for an unrecognized fmt.
        """
        pass

    def export_to_clipboard(self, fmt: str = "txt") -> None:
        """Copies the export to the clipboard (via pyperclip) formatted as
        'txt' or 'json'."""
        pass

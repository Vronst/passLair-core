from abc import ABC, abstractmethod


class BaseImporter(ABC):
    @abstractmethod
    def import_from_file(self, path: str, fmt: str) -> None:
        pass

    @abstractmethod
    def import_from_clipboard(self, fmt: str) -> None:
        pass

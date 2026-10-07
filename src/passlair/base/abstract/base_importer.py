from abc import ABC, abstractmethod

from ...dataclasses.import_result import ImportResult


class BaseImporter(ABC):
    @abstractmethod
    def import_text(self, content: str, fmt: str) -> ImportResult:
        pass

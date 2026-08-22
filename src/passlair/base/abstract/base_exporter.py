from abc import ABC, abstractmethod

class BaseExporter(ABC):

    @abstractmethod
    def export_to_file(self, path: str, fmt: str) -> None:
        pass

    @abstractmethod
    def export_to_clipboard(self, fmt: str = 'txt') -> None:
        pass

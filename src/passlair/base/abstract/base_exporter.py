from abc import ABC, abstractmethod


class BaseExporter(ABC):
    @abstractmethod
    def serialize(self, fmt: str) -> str:
        pass

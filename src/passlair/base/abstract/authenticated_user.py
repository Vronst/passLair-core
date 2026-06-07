from abc import ABC, abstractmethod


class AuthenticatedUser(ABC):
    @abstractmethod
    def get_session_key(self) -> str:
        pass

    @property
    @abstractmethod
    def user_id(self) -> str | None:
        pass

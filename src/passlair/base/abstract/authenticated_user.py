from abc import ABC, abstractmethod


class AuthenticatedUser(ABC):
    @abstractmethod
    def get_session_key(self) -> bytes:
        pass

    @property
    @abstractmethod
    def user_id(self) -> str | None:
        pass

    @classmethod
    def require(cls, user: "AuthenticatedUser") -> "AuthenticatedUser":
        """Validates a constructor argument, shared by every class that takes a user session."""
        if not isinstance(user, AuthenticatedUser):
            raise TypeError("Invalid AuthenticatedUser argument on init.")
        return user

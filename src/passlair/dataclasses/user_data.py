from .base import Base


class UserCreation(Base):
    username: str
    password: str
    salt: bytes
